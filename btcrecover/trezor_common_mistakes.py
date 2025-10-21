"""Mappings for Trezor's commonly misspelled BIP39 backup words.

The source data mirrors the list published by Trezor and groups together
words which are frequently confused with each other.  The
``TREZOR_COMMON_MISTAKE_GROUPS`` constant preserves the original groupings,
while ``TREZOR_COMMON_MISTAKES`` expands the groups into a mapping that can be
used by the seed transformation generators.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

TREZOR_COMMON_MISTAKE_GROUPS: Sequence[Tuple[str, ...]] = (
    ("able", "cable", "table"),
    ("across", "cross"),
    ("act", "art", "cat", "pact"),
    ("action", "auction"),
    ("add", "dad"),
    ("again", "gain"),
    ("age", "cage", "page", "wage"),
    ("ahead", "head"),
    ("aim", "air", "arm"),
    ("air", "hair", "pair"),
    ("all", "ball", "call", "fall", "ill", "wall"),
    ("alley", "valley"),
    ("alter", "later"),
    ("anger", "danger"),
    ("angle", "ankle"),
    ("arch", "march"),
    ("area", "arena"),
    ("arm", "army", "art", "farm", "warm"),
    ("around", "round"),
    ("arrow", "narrow"),
    ("art", "cart"),
    ("ask", "mask", "task"),
    ("aunt", "hunt"),
    ("avoid", "void"),
    ("awake", "aware"),
    ("away", "way"),
    ("bag", "bar", "tag"),
    ("ball", "call", "fall", "wall"),
    ("bar", "car", "jar"),
    ("base", "case"),
    ("battle", "cattle"),
    ("beach", "bench", "teach"),
    ("bean", "mean"),
    ("belt", "best", "melt"),
    ("best", "nest", "test", "west"),
    ("better", "bitter", "butter", "letter"),
    ("bid", "bind", "bird", "kid"),
    ("bike", "like"),
    ("bind", "bird", "blind", "find", "kind", "mind"),
    ("bitter", "butter"),
    ("blade", "blame"),
    ("blame", "flame"),
    ("blue", "blur", "glue"),
    ("blush", "brush", "flush", "slush"),
    ("boat", "goat"),
    ("body", "boy"),
    ("boil", "coil", "foil", "oil"),
    ("bone", "one", "tone", "zone"),
    ("book", "cook"),
    ("border", "order"),
    ("boring", "bring"),
    ("boss", "toss"),
    ("box", "boy", "fox"),
    ("boy", "joy", "toy"),
    ("brain", "grain", "rain", "train"),
    ("brass", "grass"),
    ("brick", "brisk", "trick"),
    ("bridge", "ridge"),
    ("brief", "grief"),
    ("bright", "right"),
    ("bring", "ring"),
    ("brisk", "risk"),
    ("broom", "room"),
    ("brown", "frown"),
    ("brush", "crush"),
    ("bulb", "bulk"),
    ("bus", "busy"),
    ("cable", "table"),
    ("cage", "cake", "case", "cave", "page", "wage"),
    ("cake", "case", "cave", "lake", "make"),
    ("call", "calm", "fall", "wall"),
    ("calm", "palm"),
    ("camp", "damp", "lamp", "ramp"),
    ("can", "car", "cat", "fan", "man", "scan", "van"),
    ("cannon", "canyon"),
    ("car", "card", "cart", "cat", "jar"),
    ("card", "cart", "hard", "yard"),
    ("cart", "cat"),
    ("case", "cash", "cause", "cave", "chase"),
    ("cash", "crash", "dash", "wash"),
    ("castle", "cattle"),
    ("cat", "chat", "fat", "hat"),
    ("catch", "match", "patch"),
    ("cause", "pause"),
    ("cave", "have", "pave", "save", "wave"),
    ("certain", "curtain"),
    ("chair", "hair"),
    ("change", "charge"),
    ("chat", "hat", "that", "what"),
    ("chef", "chief"),
    ("clap", "claw", "clay", "clip"),
    ("claw", "clay", "law"),
    ("clay", "play", "day"),
    ("click", "clock"),
    ("climb", "limb"),
    ("clip", "flip"),
    ("clock", "flock", "lock"),
    ("cloud", "loud"),
    ("clog", "dog"),
    ("clutch", "dutch"),
    ("coach", "couch"),
    ("coast", "cost", "roast", "toast"),
    ("code", "come", "core"),
    ("coil", "coin", "cool", "foil", "oil"),
    ("coin", "corn", "join"),
    ("come", "core", "home"),
    ("cook", "cool"),
    ("cool", "pool", "tool", "wool"),
    ("coral", "moral"),
    ("core", "corn", "more"),
    ("corn", "horn"),
    ("cost", "host", "post"),
    ("couch", "crouch"),
    ("cover", "hover", "over"),
    ("crack", "rack", "track"),
    ("craft", "draft"),
    ("cram", "cream"),
    ("crash", "crush", "trash"),
    ("cream", "dream"),
    ("crop", "drop"),
    ("cry", "dry", "try"),
    ("cube", "cute", "tube"),
    ("dad", "day", "mad", "sad"),
    ("damp", "lamp", "ramp"),
    ("daring", "during"),
    ("dash", "dish", "wash"),
    ("dawn", "lawn"),
    ("day", "dry", "say", "way"),
    ("deal", "dial", "real"),
    ("decade", "decide"),
    ("defy", "deny"),
    ("derive", "drive"),
    ("dice", "ice", "nice", "rice"),
    ("diet", "dirt"),
    ("dinner", "inner", "winner"),
    ("dish", "fish", "wish"),
    ("dog", "fog", "clog"),
    ("donkey", "monkey"),
    ("donor", "door"),
    ("door", "odor"),
    ("dose", "dove", "nose", "rose", "close"),
    ("dove", "love", "move"),
    ("draft", "drift"),
    ("draw", "raw"),
    ("drip", "drop", "trip"),
    ("dry", "try"),
    ("dust", "just", "must"),
    ("earn", "learn"),
    ("east", "easy", "vast"),
    ("edit", "exit"),
)


def _build_mistake_mapping(
    groups: Iterable[Sequence[str]],
) -> Dict[str, Tuple[str, ...]]:
    mapping: Dict[str, List[str]] = {}
    for group in groups:
        normalized = tuple(word.strip().lower() for word in group if word)
        for idx, word in enumerate(normalized):
            others = normalized[:idx] + normalized[idx + 1 :]
            if not others:
                continue
            alternatives = mapping.setdefault(word, [])
            for other in others:
                if other not in alternatives:
                    alternatives.append(other)
    return {word: tuple(alternatives) for word, alternatives in mapping.items()}


TREZOR_COMMON_MISTAKES: Dict[str, Tuple[str, ...]] = _build_mistake_mapping(
    TREZOR_COMMON_MISTAKE_GROUPS
)

__all__ = [
    "TREZOR_COMMON_MISTAKE_GROUPS",
    "TREZOR_COMMON_MISTAKES",
]
