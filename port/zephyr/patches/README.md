# Zephyr patches

Patches to Zephyr **v4.5.0** that the stack, or a board running it, needs. Apply
them to the Zephyr tree with `git am --3way`, in file name order:

```bash
cd <zephyr>
git am --3way <stack>/port/zephyr/patches/0001-*.patch <stack>/port/zephyr/patches/0002-*.patch
```

Only `0001` and `0002` are needed on every board. The others are board support:
apply a range only when building for that hardware. A build tree that serves
several boards from one Zephyr, like the demos workspace and its Docker image,
applies all of them.

The numbers group the patches. A new patch takes the next free number in its
group.

| Patches | Needed for | Notes |
|---------|------------|-------|
| `0001`, `0002` | **all boards** | `0001`: keyed `settings_load_one` and a delete-aware name cache in the NVS settings backend; the stack's persistent storage depends on it. `0002`: the outgoing interface from `IPV6_PKTINFO` on send (`ipi6_ifindex`); Zephyr already takes the source address from it. |
| `0011`, `0012` | Espressif SoCs with Thread (in the demos: ESP32-C5, ESP32-C6) | IEEE 802.15.4 Enhanced ACK and `get_sch_acc`. |

Since Zephyr v4.5.0 these are upstream and no longer patched here: the EFR32
IEEE 802.15.4 driver for the Silicon Labs xG24 SoCs, the source address from
`IPV6_PKTINFO` on send (the other half of the former `0002`), and the Espressif
Wi-Fi interface kept dormant until associated (the former `0013`).
