/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	device.log.Verbosef("Routine: event worker - started")

	for event := range device.tun.device.Events() {
		//device.log.Verbosef("Routine: event worker - received event %d", event)
		if event&tun.EventMTUUpdate != 0 {
			device.log.Verbosef("Routine: event worker - MTU update requested")
			mtu, err := device.tun.device.MTU()
			if err != nil {
				device.log.Errorf("failed to load updated MTU of device: %s", err)
				continue
			}
			if mtu < 0 {
				device.log.Errorf("mtu not updated to negative value: %d", mtu)
				continue
			}
			var tooLarge string
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %d)", MaxContentSize)
				mtu = MaxContentSize
			}
			old := device.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				device.log.Verbosef("Routine: event worker - MTU updated: %d%s", mtu, tooLarge)
			} else {
				device.log.Verbosef("Routine: event worker - MTU already set to %d", mtu)
			}
		}

		if event&tun.EventUp != 0 {
			device.log.Verbosef("Routine: event worker - Interface up requested")
			if err := device.Up(); err != nil {
				device.log.Errorf("Failed to bring interface up: %s", err)
			}
			device.log.Verbosef("Routine: event worker - Interface is up")
		}

		if event&tun.EventDown != 0 {
			device.log.Verbosef("Routine: event worker - Interface down requested")
			if err := device.Down(); err != nil {
				device.log.Errorf("Failed to bring interface down: %s", err)
			}
			device.log.Verbosef("Routine: event worker - Interface is down")
		}
	}

	device.log.Verbosef("Routine: event worker - stopped")
}
