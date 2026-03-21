package pg

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// embeddingCacheEntry holds data for a single cache row.
type embeddingCacheEntry struct {
	Hash      string
	Embedding []float32
}

// lookupEmbeddingCache fetches cached embeddings for the given content hashes.
// Returns a map from hash -> embedding vector. Missing hashes are simply absent.
func (s *PGMemoryStore) lookupEmbeddingCache(ctx context.Context, hashes []string, provider, model string) (map[string][]float32, error) {
	if len(hashes) == 0 {
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT hash, embedding FROM embedding_cache WHERE hash = ANY($1) AND provider = $2 AND model = $3`,
		pq.Array(hashes), provider, model,
	)
	if err != nil {
		return nil, fmt.Errorf("lookup embedding cache: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]float32, len(hashes))
	for rows.Next() {
		var hash, vecStr string
		if err := rows.Scan(&hash, &vecStr); err != nil {
			slog.Warn("embedding cache scan error", "error", err)
			continue
		}
		vec, err := parseVector(vecStr)
		if err != nil {
			slog.Warn("embedding cache parse error", "hash", hash, "error", err)
			continue
		}
		result[hash] = vec
	}
	return result, rows.Err()
}

// writeEmbeddingCache batch-upserts embedding cache entries.
func (s *PGMemoryStore) writeEmbeddingCache(ctx context.Context, entries []embeddingCacheEntry, provider, model string) error {
	if len(entries) == 0 {
		return nil
	}

	now := time.Now()
	for _, e := range entries {
		dims := len(e.Embedding)
		vecStr := vectorToString(e.Embedding)
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO embedding_cache (hash, provider, model, embedding, dims, created_at, updated_at)
			 VALUES ($1, $2, $3, $4::vector, $5, $6, $6)
			 ON CONFLICT (hash, provider, model)
			 DO UPDATE SET embedding = EXCLUDED.embedding, dims = EXCLUDED.dims, updated_at = EXCLUDED.updated_at`,
			e.Hash, provider, model, vecStr, dims, now,
		)
		if err != nil {
			return fmt.Errorf("write embedding cache hash=%s: %w", e.Hash, err)
		}
	}
	return nil
}

// parseVector converts a pgvector string like "[0.1,0.2,0.3]" into []float32.
func parseVector(s string) ([]float32, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return nil, fmt.Errorf("vector string too short: %q", s)
	}
	// Strip surrounding brackets
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	vec := make([]float32, 0, len(parts))
	for _, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 32)
		if err != nil {
			return nil, fmt.Errorf("parse vector element %q: %w", p, err)
		}
		vec = append(vec, float32(f))
	}
	return vec, nil
}
