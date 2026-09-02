package main

import "strings"

func normalizePrefix(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = strings.TrimRight(value, "/")
	if value == "" {
		return "/"
	}
	return value
}

func prefixedPath(prefix, path string) string {
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" || prefix == "/" {
		return path
	}
	return prefix + path
}
