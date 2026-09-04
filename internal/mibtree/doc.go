// Package mibtree is the lexicographic OID instance tree per named map.
//
// Compile builds a sorted slice of instance OIDs. Get, GetNext, and
// GetBulk consult that slice. CheckSet validates access, type, and
// range/size; overlay apply is the store, not this package.
package mibtree
