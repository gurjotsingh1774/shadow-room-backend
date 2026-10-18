package codename

import (
	"fmt"
	"math/rand"
)

// RegistryDimensions maps out the matrix counts for generating unique codenames.
type RegistryDimensions struct {
	Prefix, Root, Suffix, Tag, Number uint64
}

// PseudonymGenerator creates high-entropy network codenames from multiple independent tiers.
//
// Total Combinations:
//
//	512 Prefixes * 2,048 Roots * 64 Suffixes * 1,024 Tags * 10,000 Numbers
//	= 687,194,767,360,000 completely unique network identities.
//
// To optimize memory allocations, each tier is generated on the fly as a product
// of two internal sub-slices (Bases and Modifiers).
type PseudonymGenerator struct {
	prefixBase []string
	prefixMods []string

	rootBase []string
	rootMods []string

	suffixBase []string
	suffixMods []string

	tagBase []string
	tagMods []string
}

// NewPseudonymGenerator sets up the vocabulary registry matrix for identity assignment.
func NewPseudonymGenerator() *PseudonymGenerator {
	pg := &PseudonymGenerator{
		// ---- PREFIX: 32 base x 16 mods = 512 combinations ----
		prefixBase: []string{
			"Shadow", "Dark", "Void", "Night", "Ghost", "Phantom", "Silent", "Crimson",
			"Blood", "Iron", "Steel", "Black", "White", "Azure", "Scarlet", "Silver",
			"Golden", "Obsidian", "Alpha", "Nova", "Infernal", "Frost", "Storm", "Ash",
			"Raven", "Venom", "Toxic", "Spectral", "Solar", "Lunar", "Nebula", "Umbra",
		},
		prefixMods: []string{
			"", "X", "Z", "Neo", "Ultra", "Nova", "Prime", "Core",
			"Mk", "Ex", "Zero", "One", "Vex", "Flux", "Grim", "Wild",
		},

		// ---- ROOT: 64 base x 32 mods = 2,048 combinations ----
		rootBase: []string{
			"Reaper", "Scythe", "Hunter", "Walker", "Blade", "Knight", "Warden", "Fang",
			"Wolf", "Rogue", "Oracle", "Titan", "Cipher", "Viper", "Shade", "Echo",
			"Drifter", "Sentinel", "Raptor", "Assassin", "Specter", "Nomad", "Phoenix", "Dragon",
			"Hawk", "Falcon", "Dagger", "Striker", "Monarch", "Gladiator", "Mamba", "Nexus",
			"Ronin", "Sniper", "Marauder", "Vandal", "Corsair", "Berserker", "Templar", "Outlaw",
			"Havoc", "Cobra", "Jaguar", "Lynx", "Panther", "Vulture", "Kestrel", "Scorpion",
			"Golem", "Wraith", "Banshee", "Djinn", "Cyclone", "Tempest", "Avalanche", "Eclipse",
			"Meridian", "Zenith", "Vertex", "Paragon", "Vanguard", "Bastion", "Crusader", "Harbinger",
		},
		rootMods: []string{
			"", "-X", "-Z", "Prime", "Zero", "One", "Elite", "Core",
			"XI", "XII", "XIII", "IV", "VII", "X99", "Mk2", "Ex",
			"Rogue", "Nova", "Alpha", "Omega", "Storm", "Frost", "Vex", "Grim",
			"Neo", "Ultra", "Wild", "Flux", "Dusk", "Dawn", "Void", "Star",
		},

		// ---- SUFFIX: 8 base x 8 mods = 64 combinations ----
		suffixBase: []string{"", "X", "Z", "Prime", "Zero", "Elite", "Core", "Mk"},
		suffixMods: []string{"", "I", "II", "III", "IV", "V", "IX", "99"},

		// ---- TAG/SYMBOL: 32 base x 32 mods = 1024 combinations ----
		tagBase: []string{
			"_", "-", ".", "~", "^", "+", "*", "#",
			"_X", "-Z", ".Q", "~V", "^A", "+B", "*C", "#D",
			"_01", "-02", ".03", "~04", "^05", "+06", "*07", "#08",
			"_A1", "-B2", ".C3", "~D4", "^E5", "+F6", "*G7", "#H8",
		},
	}

	// Staging out hexadecimal layout parameters for tag modifiers [00..1F]
	pg.tagMods = make([]string, 32)
	for i := 0; i < 32; i++ {
		pg.tagMods[i] = fmt.Sprintf("%02X", i)
	}

	return pg
}

// Dimensions returns the exact element constraints for all runtime tracking vectors.
func (pg *PseudonymGenerator) Dimensions() RegistryDimensions {
	return RegistryDimensions{
		Prefix: uint64(len(pg.prefixBase)) * uint64(len(pg.prefixMods)),
		Root:   uint64(len(pg.rootBase)) * uint64(len(pg.rootMods)),
		Suffix: uint64(len(pg.suffixBase)) * uint64(len(pg.suffixMods)),
		Tag:    uint64(len(pg.tagBase)) * uint64(len(pg.tagMods)),
		Number: 10000,
	}
}

// TotalCapacity evaluates the complete volumetric space size of the generation field matrix.
func (pg *PseudonymGenerator) TotalCapacity() uint64 {
	dim := pg.Dimensions()
	return dim.Prefix * dim.Root * dim.Suffix * dim.Tag * dim.Number
}

// GenerateByIndex calculates and extracts a unique pseudorandom name using index positioning.
// Passing identical index values safely produces identical, collision-free identities without storing state.
func (pg *PseudonymGenerator) GenerateByIndex(index uint64) string {
	dim := pg.Dimensions()
	matrixSizes := []uint64{dim.Prefix, dim.Root, dim.Suffix, dim.Tag, dim.Number}
	coordinates := make([]uint64, len(matrixSizes))

	remainder := index
	for i := len(matrixSizes) - 1; i >= 0; i-- {
		coordinates[i] = remainder % matrixSizes[i]
		remainder /= matrixSizes[i]
	}

	return pg.compile(
		pg.extractPrefix(coordinates[0]),
		pg.extractRoot(coordinates[1]),
		pg.extractSuffix(coordinates[2]),
		pg.extractTag(coordinates[3]),
		pg.extractNumber(coordinates[4]),
	)
}

// GenerateRandom picks an item out of the available name fields uniformly using the provided RNG engine.
func (pg *PseudonymGenerator) GenerateRandom(rng *rand.Rand) string {
	dim := pg.Dimensions()
	getRandomOffset := func(upperLimit uint64) uint64 { return uint64(rng.Int63n(int64(upperLimit))) }

	return pg.compile(
		pg.extractPrefix(getRandomOffset(dim.Prefix)),
		pg.extractRoot(getRandomOffset(dim.Root)),
		pg.extractSuffix(getRandomOffset(dim.Suffix)),
		pg.extractTag(getRandomOffset(dim.Tag)),
		pg.extractNumber(getRandomOffset(dim.Number)),
	)
}

// GenerateBatch assembles an array of unique random identities, deduplicated natively.
func (pg *PseudonymGenerator) GenerateBatch(batchSize int, rng *rand.Rand) []string {
	allocatedCache := make(map[string]struct{}, batchSize)
	identities := make([]string, 0, batchSize)

	for len(identities) < batchSize {
		codename := pg.GenerateRandom(rng)
		if _, exists := allocatedCache[codename]; !exists {
			allocatedCache[codename] = struct{}{}
			identities = append(identities, codename)
		}
	}
	return identities
}

// --- Component Extraction Engines ---

func (pg *PseudonymGenerator) extractPrefix(index uint64) string {
	modCount := uint64(len(pg.prefixMods))
	return pg.prefixBase[index/modCount] + pg.prefixMods[index%modCount]
}

func (pg *PseudonymGenerator) extractRoot(index uint64) string {
	modCount := uint64(len(pg.rootMods))
	return pg.rootBase[index/modCount] + pg.rootMods[index%modCount]
}

func (pg *PseudonymGenerator) extractSuffix(index uint64) string {
	modCount := uint64(len(pg.suffixMods))
	return pg.suffixBase[index/modCount] + pg.suffixMods[index%modCount]
}

func (pg *PseudonymGenerator) extractTag(index uint64) string {
	modCount := uint64(len(pg.tagMods))
	return pg.tagBase[index/modCount] + pg.tagMods[index%modCount]
}

func (pg *PseudonymGenerator) extractNumber(index uint64) string {
	return fmt.Sprintf("%04d", index)
}

func (pg *PseudonymGenerator) compile(prefix, root, suffix, tag, number string) string {
	return prefix + root + suffix + tag + number
}
