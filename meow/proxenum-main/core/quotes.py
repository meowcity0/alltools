import random
from typing import Tuple

QUOTES: list[Tuple[str, str]] = [
    (
        "Not all who wander are lost.",
        "彷徨うすべての者が、迷っているわけではない。",
    ),
    (
        "The obstacle is the way.",
        "障害こそが道だ。",
    ),
    (
        "You don't have to be great to start, but you have to start to be great.",
        "始めるために偉大である必要はない。だが、偉大になるためには始めなければならない。",
    ),
    (
        "It's okay to not know everything. That's what makes the journey worth taking.",
        "すべてを知らなくていい。それが旅を価値あるものにする。",
    ),
    (
        "Rest if you must, but don't you quit.",
        "休んでもいい、でも諦めるな。",
    ),
    (
        "Every expert was once a beginner.",
        "すべての達人は、かつて初心者だった。",
    ),
    (
        "The magic isn't in the destination. It's in every step of the journey.",
        "魔法は目的地にあるのではない。旅のひとつひとつの歩みの中にある。",
    ),
    (
        "Small progress is still progress.",
        "小さな前進も、前進だ。",
    ),
    (
        "You've already come further than you think.",
        "あなたはすでに、自分が思うよりもずっと遠くまで来ている。",
    ),
    (
        "The map doesn't show every path. Some must be walked to be found.",
        "地図にはすべての道が載っているわけではない。歩いてはじめて見えてくる道もある。",
    ),
    (
        "Trust the process. Even in the dark, roots grow.",
        "プロセスを信じろ。暗闇の中でも、根は育つ。",
    ),
    (
        "Take a breath. You've handled hard things before.",
        "ひと息ついて。あなたは以前も難しいことを乗り越えてきた。",
    ),
    (
        "Even the longest road begins with a single step.",
        "どんな長い道も、最初の一歩から始まる。",
    ),
    (
        "It doesn't matter how slow you go, as long as you don't stop.",
        "どれだけゆっくりでもいい、止まらなければ前に進んでいる。",
    ),
]


def get_random_quote() -> Tuple[str, str]:
    return random.choice(QUOTES)
