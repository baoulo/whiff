/// What a piece of emitted text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRole {
    /// Running body text.
    Body,
    /// The document title.
    Title,
    /// A heading of the given level (1 = top).
    Heading(u8),
    /// Caption or alt text.
    Caption,
    /// Comment / annotation.
    Comment,
    /// Text found in metadata fields.
    Metadata,
    /// Source code.
    Code,
}

/// One emitted piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChunk {
    /// Role.
    pub role: TextRole,
    /// Text.
    pub text: String,
}

/// Text collected from extractors for the text analyzers, capped in size.
#[derive(Debug, Clone, Default)]
pub struct TextStore {
    chunks: Vec<TextChunk>,
    bytes: usize,
    limit: usize,
    truncated: bool,
}

impl TextStore {
    /// A store accepting at most `limit` bytes.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit, ..Self::default() }
    }

    /// Add text; anything beyond the limit is dropped (cut on a char boundary).
    pub fn push(&mut self, role: TextRole, text: &str) {
        let room = self.limit.saturating_sub(self.bytes);
        if room == 0 {
            if !text.is_empty() {
                self.truncated = true;
            }
            return;
        }
        let mut end = text.len().min(room);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end < text.len() {
            self.truncated = true;
        }
        if end > 0 {
            self.bytes += end;
            self.chunks.push(TextChunk { role, text: text[..end].to_string() });
        }
    }

    /// All chunks in emission order.
    pub fn chunks(&self) -> &[TextChunk] {
        &self.chunks
    }

    /// Chunks with the given role.
    pub fn by_role(&self, role: TextRole) -> impl Iterator<Item = &str> {
        self.chunks.iter().filter(move |c| c.role == role).map(|c| c.text.as_str())
    }

    /// Total bytes stored.
    pub fn len(&self) -> usize {
        self.bytes
    }

    /// Whether nothing was stored.
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Whether text was dropped because of the limit.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
