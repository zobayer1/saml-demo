package helpers

import "strings"

func ExtractSPName(entityID string) string {
	if strings.Contains(entityID, "sp1") {
		return "Service Provider 1"
	} else if strings.Contains(entityID, "sp2") {
		return "Service Provider 2"
	}
	if strings.HasPrefix(entityID, "http") {
		parts := strings.Split(entityID, "/")
		if len(parts) > 2 {
			return parts[2] // domain part
		}
	}
	return "External Service"
}
