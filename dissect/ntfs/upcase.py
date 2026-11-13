from __future__ import annotations

UPCASE_TABLE_SIZE = 0x20000
"""Expected size in bytes of the ``$UpCase`` data: one 16-bit mapping for each UTF-16 code unit."""


class UpcaseTable:
    """Volume specific filename upcase mapping, as stored in the ``$UpCase`` file of an NTFS volume.

    The table holds one little-endian 16-bit mapping for each UTF-16 code unit, mapping every character
    to the uppercase equivalent that this volume's filename indexes are sorted by. Mapping every code
    unit individually never changes the length of a name, which is required for comparisons to stay
    consistent with the on-disk index order.

    Args:
        data: The contents of the ``$UpCase`` ``$DATA`` stream.

    Raises:
        ValueError: If the data is too small to be a valid upcase table.
    """

    def __init__(self, data: bytes):
        if len(data) < UPCASE_TABLE_SIZE:
            raise ValueError(f"Invalid $UpCase table size: {len(data)}")
        self.data = data

    def uppercase(self, name: str) -> str:
        """Return the uppercase form of ``name`` according to this volume's upcase table."""
        data = self.data
        result = []
        for char in name:
            unit = ord(char)
            if unit > 0xFFFF:
                # $UpCase only covers the BMP, characters outside of it are left unchanged
                result.append(char)
            else:
                offset = unit * 2
                result.append(chr(data[offset] | (data[offset + 1] << 8)))
        return "".join(result)


def fallback_uppercase(name: str) -> str:
    """Best-effort length-preserving uppercase of ``name`` using Unicode rules.

    Used as a degradation when a volume has no usable ``$UpCase`` table. Characters whose uppercase
    form consists of multiple characters (e.g. ``ß``) are left unchanged, so the result always has
    the same number of characters as the input and comparisons stay consistent with the index order.
    """
    result = []
    for char in name:
        upper = char.upper()
        result.append(upper if len(upper) == 1 else char)
    return "".join(result)
