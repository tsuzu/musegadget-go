package executor

import (
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"

	"musegadget"
	"musegadget/wirejson"
)

// DeviceHealth implements the device.health command, mirroring the
// reference's /proc and /sys reads.
func DeviceHealth() wirejson.Obj {
	health := wirejson.Obj{}
	health = append(health, wirejson.Pair{Key: "version", Value: musegadget.Version})
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		health = append(health, wirejson.Pair{Key: "hostname", Value: hostname})
	}
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			if uptime, err := strconv.ParseFloat(fields[0], 64); err == nil {
				health = append(health, wirejson.Pair{Key: "uptime_s", Value: int64(uptime)})
			}
		}
	}
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 3 {
			load := []any{}
			ok := true
			for _, field := range fields[:3] {
				value, err := strconv.ParseFloat(field, 64)
				if err != nil {
					ok = false
					break
				}
				load = append(load, roundTo(value, 2))
			}
			if ok {
				health = append(health, wirejson.Pair{Key: "load", Value: load})
			}
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		meminfo := map[string]int64{}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) == 0 {
				continue
			}
			if value, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				meminfo[strings.TrimSpace(parts[0])] = value
			}
		}
		total, hasTotal := meminfo["MemTotal"]
		available, hasAvailable := meminfo["MemAvailable"]
		if hasTotal && hasAvailable {
			health = append(health, wirejson.Pair{Key: "memory_mb", Value: wirejson.Obj{
				{Key: "total", Value: total / 1024},
				{Key: "available", Value: available / 1024},
			}})
		}
	}
	var statfs syscall.Statfs_t
	if err := syscall.Statfs("/", &statfs); err == nil {
		total := float64(statfs.Blocks*uint64(statfs.Bsize)) / 1e9
		free := float64(statfs.Bavail*uint64(statfs.Bsize)) / 1e9
		health = append(health, wirejson.Pair{Key: "disk_gb", Value: wirejson.Obj{
			{Key: "total", Value: roundTo(total, 1)},
			{Key: "free", Value: roundTo(free, 1)},
		}})
	}
	if raw, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if milliDegrees, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			health = append(health, wirejson.Pair{Key: "temperature_c", Value: float64(milliDegrees) / 1000})
		}
	}
	if raw, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		model := strings.Trim(string(raw), "\x00\n")
		if model != "" {
			health = append(health, wirejson.Pair{Key: "model", Value: model})
		}
	}
	return health
}

// roundTo rounds like Python's round(): half to even.
func roundTo(value float64, digits int) float64 {
	scale := math.Pow(10, float64(digits))
	return math.RoundToEven(value*scale) / scale
}
