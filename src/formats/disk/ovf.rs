//! Virtual appliances: OVF descriptors (`.ovf`, DMTF Open Virtualization
//! Format XML) and OVA packages (a tar archive with the descriptor first,
//! then a manifest, an optional certificate and the disks). The
//! descriptor gives the product (name, vendor, version, URLs), the
//! annotation and licence agreement, the guest OS, the virtual hardware
//! (system type, CPUs, memory, network adapters, disks and drives), the
//! disks with their capacity and format, the networks and the files
//! referenced. An OVA also reports its manifest's hash algorithm and
//! whether it is signed, lists its entries, and hands them on (the VMDK
//! disks are described in turn).
//!
//! Specification: DMTF DSP0243 (OVF 1.1 and 2.1).

use serde_json::{Map, Value, json};

use super::archive::{self, Kind, Stored, stored_children};
use super::xml::{Ev, Flow, walk};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for OVF descriptors and OVA packages.
pub struct Ovf;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.ovf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ova",
            name: "Open Virtualization Format archive",
            family: "disk",
            mimes: &["application/ovf"],
            extensions: &["ova"],
            magic: &[],
            parent: Some("tar"),
        },
        FormatSpec {
            id: "ovf",
            name: "Open Virtualization Format descriptor",
            family: "disk",
            mimes: &["application/ovf+xml"],
            extensions: &["ovf"],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

/// Descriptor bytes parsed at most.
const MAX_OVF: u64 = 8 << 20;
/// Items listed per kind at most.
const MAX_ITEMS: usize = 64;

impl Extractor for Ovf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let names = archive::tar::head_names(probe.head, 1);
        let ovf_first = names
            .first()
            .and_then(|n| std::path::Path::new(n).extension())
            .is_some_and(|x| x.eq_ignore_ascii_case("ovf"));
        if ovf_first {
            return Some(Sniff { format: "ova", confidence: 0.96 });
        }
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(4096)]).ok()?;
        (head.contains("Envelope") && head.contains("schemas.dmtf.org/ovf/envelope"))
            .then_some(Sniff { format: "ovf", confidence: 0.96 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "ovf" {
            let (bytes, _) = cx.read_bytes(src)?;
            descriptor(&String::from_utf8_lossy(&bytes), cx);
            return Ok(());
        }
        let mut ovf = None;
        let mut manifest = None;
        let mut signed = false;
        let mut pending: Vec<Stored> = Vec::new();
        let listing = archive::tar::list(src, cx, |e, at, size, sparse, cx| {
            if e.kind != Kind::File || sparse {
                return;
            }
            let ext = std::path::Path::new(&e.path).extension().map(std::ffi::OsStr::to_ascii_lowercase);
            let ext = ext.as_ref().and_then(|x| x.to_str()).unwrap_or("");
            match ext {
                "ovf" if ovf.is_none() => ovf = Some((at, size)),
                "mf" => manifest = Some((at, size)),
                "cert" => signed = true,
                _ => {}
            }
            if archive::wanted(e) && pending.len() < cx.child_room() && ext != "ovf" {
                pending.push((e.path.clone(), at, size));
            }
        })?;
        if let Some((at, size)) = manifest {
            let mf = src.read_vec(at, usize::try_from(size.min(1 << 20)).unwrap_or(0))?;
            let mf = String::from_utf8_lossy(&mf);
            if let Some(algo) =
                mf.lines().find_map(|l| l.split('(').next().filter(|a| a.starts_with("SHA")).map(str::to_string))
            {
                cx.format_set("manifest", algo);
            }
        }
        cx.format_set("signed", signed);
        cx.security().signed(signed);
        if let Some((at, size)) = ovf {
            let text = src.read_vec(at, usize::try_from(size.min(MAX_OVF)).unwrap_or(0))?;
            descriptor(&String::from_utf8_lossy(&text), cx);
        } else {
            cx.warn("no .ovf descriptor in the archive");
        }
        listing.inventory.report(cx, src.len());
        stored_children(src, cx, pending)
    }
}

crate::register_extractor!(Ovf);

/// Bytes in an OVF allocation unit (`byte * 2^30`, `MegaBytes`).
fn unit_bytes(unit: &str) -> u64 {
    let u = unit.replace(' ', "").to_ascii_lowercase();
    if let Some(p) = u.strip_prefix("byte*2^") {
        return p.parse::<u32>().ok().filter(|&p| p < 64).map_or(1, |p| 1u64 << p);
    }
    match u.as_str() {
        "kilobytes" | "kb" => 1 << 10,
        "megabytes" | "mb" => 1 << 20,
        "gigabytes" | "gb" => 1 << 30,
        "terabytes" | "tb" => 1 << 40,
        _ => 1,
    }
}

/// Resource types of virtual hardware items (`CIM_ResourceAllocationSettingData`).
fn resource(t: &str) -> Option<&'static str> {
    Some(match t {
        "3" => "cpu",
        "4" => "memory",
        "5" => "ide_controller",
        "6" => "scsi_controller",
        "10" => "ethernet",
        "14" => "floppy",
        "15" | "16" => "cd_drive",
        "17" => "disk",
        "20" => "sata_controller",
        "21" | "23" => "usb_controller",
        "24" => "graphics",
        "35" => "sound",
        _ => return None,
    })
}

#[allow(clippy::too_many_lines)] // one walk over the envelope's sections
fn descriptor(xml: &str, cx: &mut Context<'_>) {
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut facts = Map::new();
    let (mut files, mut disks, mut networks, mut hardware) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut item: Map<String, Value> = Map::new();
    let mut annotation = None;
    let mut eula = false;
    let mut os = Map::new();
    let mut vs_count = 0;
    let result = walk(xml, cx, |ev| {
        match ev {
            Ev::Open(tag, empty) => {
                let parent = stack.last().map(String::as_str);
                match (tag.name.as_str(), parent) {
                    ("File", Some("References")) if files.len() < MAX_ITEMS => {
                        let mut m = Map::new();
                        if let Some(h) = tag.attr("href") {
                            m.insert("href".into(), json!(h));
                        }
                        if let Some(s) = tag.attr("size").and_then(|s| s.parse::<u64>().ok()) {
                            m.insert("size_bytes".into(), json!(s));
                        }
                        files.push(Value::Object(m));
                    }
                    ("Disk", Some("DiskSection")) if disks.len() < MAX_ITEMS => {
                        let mut m = Map::new();
                        if let Some(id) = tag.attr("diskId") {
                            m.insert("id".into(), json!(id));
                        }
                        if let Some(c) = tag.attr("capacity").and_then(|c| c.parse::<u64>().ok()) {
                            let unit = tag.attr("capacityAllocationUnits").map_or(1, unit_bytes);
                            m.insert("capacity_bytes".into(), json!(c.saturating_mul(unit)));
                        }
                        if let Some(f) = tag.attr("format") {
                            let short = f.rsplit('#').next().unwrap_or(f);
                            m.insert("format".into(), json!(short));
                        }
                        if let Some(r) = tag.attr("fileRef") {
                            m.insert("file".into(), json!(r));
                        }
                        disks.push(Value::Object(m));
                    }
                    ("Network", Some("NetworkSection")) if networks.len() < MAX_ITEMS => {
                        if let Some(n) = tag.attr("name") {
                            networks.push(json!(n));
                        }
                    }
                    ("VirtualSystem", _) => {
                        vs_count += 1;
                        if let Some(id) = tag.attr("id")
                            && vs_count == 1
                        {
                            facts.insert("virtual_system".into(), json!(id));
                        }
                    }
                    ("OperatingSystemSection", _) => {
                        if let Some(id) = tag.attr("id") {
                            os.insert("id".into(), json!(id));
                        }
                        if let Some(t) = tag.attr("osType") {
                            os.insert("type".into(), json!(t));
                        }
                    }
                    ("Item" | "StorageItem" | "EthernetPortItem", _) => item.clear(),
                    ("EulaSection", _) => eula = true,
                    _ => {}
                }
                if !empty {
                    stack.push(tag.name.clone());
                }
                text.clear();
            }
            Ev::Text(t) => {
                if text.len() < 4096 {
                    text.push_str(t);
                }
            }
            Ev::Close(name) => {
                stack.pop();
                let parent = stack.last().map(String::as_str);
                let value = text.trim().to_string();
                text.clear();
                match (name, parent) {
                    (
                        "Product" | "Vendor" | "Version" | "FullVersion" | "ProductUrl" | "VendorUrl",
                        Some("ProductSection"),
                    ) => {
                        let key = match name {
                            "Product" => "product",
                            "Vendor" => "vendor",
                            "Version" => "version",
                            "FullVersion" => "full_version",
                            "ProductUrl" => "product_url",
                            _ => "vendor_url",
                        };
                        if !value.is_empty() {
                            facts.entry(key).or_insert_with(|| json!(value));
                        }
                    }
                    ("Name", Some("VirtualSystem")) if !value.is_empty() => {
                        facts.entry("name").or_insert_with(|| json!(value));
                    }
                    ("Annotation", Some("AnnotationSection")) if !value.is_empty() => annotation = Some(value),
                    ("Description", Some("OperatingSystemSection")) if !value.is_empty() => {
                        os.insert("description".into(), json!(value));
                    }
                    ("VirtualSystemType", _) if !value.is_empty() => {
                        facts.insert("system_type".into(), json!(value));
                    }
                    (
                        "ResourceType" | "VirtualQuantity" | "AllocationUnits" | "ElementName" | "ResourceSubType",
                        Some("Item" | "StorageItem" | "EthernetPortItem"),
                    ) => {
                        item.insert(name.into(), json!(value));
                    }
                    ("Item" | "StorageItem" | "EthernetPortItem", _) => {
                        let ty = item.get("ResourceType").and_then(Value::as_str).and_then(resource);
                        if let Some(ty) = ty
                            && hardware.len() < MAX_ITEMS
                        {
                            let mut m = Map::new();
                            m.insert("type".into(), json!(ty));
                            let qty =
                                item.get("VirtualQuantity").and_then(Value::as_str).and_then(|q| q.parse::<u64>().ok());
                            match (ty, qty) {
                                ("memory", Some(q)) => {
                                    let unit =
                                        item.get("AllocationUnits").and_then(Value::as_str).map_or(1 << 20, unit_bytes);
                                    m.insert("bytes".into(), json!(q.saturating_mul(unit)));
                                }
                                ("cpu", Some(q)) => {
                                    m.insert("count".into(), json!(q));
                                }
                                _ => {}
                            }
                            if let Some(sub) = item.get("ResourceSubType") {
                                m.insert("subtype".into(), sub.clone());
                            }
                            hardware.push(Value::Object(m));
                        }
                    }
                    _ => {}
                }
            }
        }
        Flow::Continue
    });
    if let Err(e) = result {
        cx.warn(format!("descriptor XML: {e}"));
    }
    if let Some(Value::String(p)) = facts.get("product").or_else(|| facts.get("name")) {
        cx.content().title(p.clone());
    }
    if let Some(Value::String(v)) = facts.get("vendor") {
        cx.content().author(v.clone());
    }
    if let Some(a) = annotation {
        cx.content().description(a.clone());
        facts.insert("annotation".into(), json!(a));
    }
    if eula {
        facts.insert("eula".into(), json!(true));
    }
    if vs_count > 1 {
        facts.insert("virtual_systems".into(), json!(vs_count));
    }
    for (k, v) in facts {
        cx.format_set(&k, v);
    }
    if !os.is_empty() {
        cx.format_set("guest_os", Value::Object(os));
    }
    let cpus: u64 = hardware.iter().filter(|h| h["type"] == "cpu").filter_map(|h| h["count"].as_u64()).sum();
    if cpus > 0 {
        cx.format_set("cpus", cpus);
    }
    if let Some(m) = hardware.iter().find(|h| h["type"] == "memory").and_then(|h| h["bytes"].as_u64()) {
        cx.format_set("memory_bytes", m);
    }
    for (key, list) in [("hardware", hardware), ("disks", disks), ("networks", networks), ("references", files)] {
        if !list.is_empty() {
            cx.format_set(key, list);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(unit_bytes("byte * 2^30"), 1 << 30);
        assert_eq!(unit_bytes("MegaBytes"), 1 << 20);
        assert_eq!(resource("17"), Some("disk"));
    }

    crate::fixture_tests!("ova", "ovf");
}
