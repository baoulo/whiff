// Copyright 2026 Harbour Systems
using System;
using System.Collections.Generic;
using static System.Math;

namespace Harbour.Services
{
    /// <summary>Keeps track of boats.</summary>
    public sealed class BoatService
    {
        private readonly List<string> _boats = new();

        public void Add(string name) => _boats.Add(name);

        // FIXME: not thread safe
        public int Count => _boats.Count;
    }

    public record Berth(int Id, string Size);

    public enum TideKind { High, Low }
}
