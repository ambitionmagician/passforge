#!/usr/bin/env python3
"""passforge - Generate secure passphrases and passwords."""

import argparse
import math
import secrets
import sys

WORDLIST = [
    "able", "about", "above", "after", "again", "age", "agree", "air", "all",
    "also", "am", "among", "animal", "another", "answer", "any", "around",
    "arrive", "art", "as", "ask", "at", "attack", "attention", "attorney",
    "audience", "author", "authority", "available", "avoid", "baby", "back",
    "bad", "bag", "ball", "bar", "base", "be", "beat", "beautiful", "because",
    "become", "bed", "before", "begin", "behavior", "behind", "believe", "benefit",
    "best", "better", "between", "beyond", "big", "bill", "billion", "bit", "black",
    "blood", "blue", "board", "body", "book", "born", "both", "box", "boy", "break",
    "bring", "brother", "budget", "build", "building", "business", "but", "buy",
    "by", "call", "camera", "campaign", "can", "cancer", "candidate", "capital",
    "car", "card", "care", "career", "carry", "case", "catch", "cause", "cell",
    "center", "central", "century", "certain", "certainly", "chair", "challenge",
    "chance", "change", "character", "charge", "check", "child", "choice", "choose",
    "church", "citizen", "city", "civil", "claim", "class", "clean", "clear",
    "clearly", "close", "coach", "cold", "collection", "college", "color", "come",
    "commercial", "common", "community", "company", "compare", "computer", "concern",
    "condition", "conference", "Congress", "consider", "consumer", "contain", "continue",
    "control", "cost", "could", "country", "couple", "course", "court", "cover",
    "create", "crime", "cultural", "culture", "cup", "current", "customer", "cut",
    "dark", "data", "daughter", "day", "dead", "deal", "death", "debate", "decade",
    "decide", "decision", "deep", "defense", "degree", "Democrat", "democratic",
    "describe", "design", "despite", "detail", "determine", "develop", "development",
    "die", "difference", "different", "difficult", "dinner", "direction", "director",
    "discover", "discuss", "discussion", "disease", "do", "doctor", "dog", "door",
    "down", "draw", "dream", "drive", "drop", "drug", "during", "each", "early",
    "east", "easy", "eat", "economic", "economy", "edge", "education", "effect",
    "effort", "eight", "either", "election", "else", "employee", "end", "energy",
    "enjoy", "enough", "enter", "entire", "environment", "environmental", "especially",
    "establish", "even", "evening", "event", "ever", "every", "everybody", "everyone",
    "everything", "evidence", "exactly", "example", "executive", "exist", "expect",
    "experience", "expert", "explain", "eye", "face", "fact", "factor", "fail",
    "fall", "family", "far", "fast", "father", "fear", "federal", "feel", "feeling",
    "few", "field", "fight", "figure", "fill", "film", "final", "finally", "financial",
    "find", "fine", "finger", "finish", "fire", "firm", "first", "fish", "five",
    "floor", "fly", "focus", "follow", "food", "foot", "for", "force", "foreign",
    "forget", "former", "formally", "forward", "four", "free", "friend", "from",
    "front", "full", "fund", "future", "garden", "gas", "general", "generation",
    "get", "girl", "give", "glass", "go", "goal", "god", "good", "government",
    "great", "green", "ground", "group", "grow", "growth", "guess", "gun", "guy",
    "hair", "half", "hand", "hang", "happen", "happy", "hard", "have", "he", "head",
    "health", "hear", "heart", "heat", "heavy", "help", "her", "here", "herself",
    "high", "him", "himself", "his", "history", "hit", "hold", "home", "hope",
    "hospital", "hot", "hotel", "hour", "house", "how", "however", "huge", "human",
    "hundred", "husband", "I", "idea", "identify", "if", "image", "imagine", "impact",
    "important", "improve", "in", "include", "including", "increase", "indeed",
    "indicate", "individual", "industry", "information", "inside", "instead",
    "institution", "interest", "interesting", "international", "interview", "into",
    "investment", "involve", "issue", "it", "item", "its", "itself", "job", "join",
    "just", "keep", "key", "kid", "kill", "kind", "kitchen", "know", "knowledge",
    "land", "language", "large", "last", "late", "later", "laugh", "law", "lay",
    "lead", "leader", "learn", "least", "leave", "left", "leg", "legal", "less",
    "let", "letter", "level", "lie", "life", "light", "like", "likely", "line",
    "list", "listen", "little", "live", "local", "long", "look", "lose", "loss",
    "lot", "love", "low", "machine", "magazine", "main", "maintain", "major",
    "majority", "make", "man", "manage", "management", "manager", "many", "market",
    "marriage", "material", "matter", "may", "maybe", "me", "mean", "measure",
    "media", "medical", "meet", "meeting", "member", "memory", "mention", "message",
    "method", "middle", "might", "military", "million", "mind", "minute", "miss",
    "mission", "model", "modern", "moment", "money", "month", "more", "morning",
    "most", "mother", "mouth", "move", "movement", "movie", "Mrs", "much", "music",
    "must", "my", "myself", "name", "nation", "national", "natural", "nature",
    "near", "nearly", "necessary", "need", "network", "never", "new", "news",
    "newspaper", "next", "nice", "night", "no", "none", "nor", "north", "not",
    "note", "nothing", "notice", "now", "number", "occur", "of", "off", "offer",
    "office", "officer", "official", "often", "oh", "oil", "ok", "old", "on", "once",
    "one", "only", "onto", "open", "operation", "opportunity", "option", "or",
    "order", "organization", "other", "others", "our", "out", "outside", "over",
    "own", "owner", "page", "pain", "painting", "paper", "parent", "part", "participant",
    "particular", "particularly", "partner", "party", "pass", "past", "patient",
    "pattern", "pay", "peace", "people", "per", "perform", "performance", "perhaps",
    "period", "person", "personal", "phone", "physical", "pick", "picture", "piece",
    "place", "plan", "plant", "play", "player", "PM", "point", "police", "policy",
    "political", "politics", "poor", "popular", "population", "position", "positive",
    "possible", "power", "practice", "prepare", "present", "president", "pressure",
    "pretty", "prevent", "price", "private", "probably", "problem", "process", "produce",
    "product", "production", "professional", "professor", "program", "project", "property",
    "protect", "prove", "provide", "public", "pull", "purpose", "push", "put", "quality",
    "question", "quickly", "quite", "race", "radio", "raise", "range", "rate", "rather",
    "reach", "read", "ready", "real", "reality", "realize", "really", "reason", "receive",
    "recent", "recently", "recognize", "record", "red", "reduce", "reflect", "region",
    "relate", "relationship", "religious", "remain", "remember", "remove", "report",
    "represent", "Republican", "require", "research", "resource", "respond",
    "response", "rest", "result", "return", "reveal", "rich", "right", "rise",
    "risk", "road", "rock", "role", "room", "rule", "run", "safe", "same", "save",
    "say", "scene", "school", "science", "scientist", "score", "sea", "season",
    "seat", "second", "section", "security", "see", "seek", "seem", "sell", "send",
    "senior", "sense", "series", "serious", "serve", "service", "set", "seven",
    "several", "shake", "shall", "shape", "share", "she", "shoot", "shop", "short",
    "shot", "should", "shoulder", "show", "side", "sign", "significant", "similar",
    "simple", "simply", "since", "sing", "single", "sister", "sit", "site", "situation",
    "six", "size", "skill", "skin", "small", "smile", "so", "social", "society",
    "soldier", "some", "somebody", "someone", "something", "sometimes", "son", "song",
    "soon", "sort", "sound", "source", "south", "southern", "space", "speak", "special",
    "specific", "speech", "spend", "sport", "spring", "staff", "stage", "stand",
    "standard", "star", "start", "state", "statement", "station", "stay", "step",
    "still", "stock", "stop", "store", "story", "strategy", "street", "strong",
    "structure", "student", "study", "stuff", "style", "subject", "success", "successful",
    "such", "suddenly", "suffer", "suggest", "summer", "support", "sure", "surface",
    "system", "table", "take", "talk", "task", "tax", "teach", "teacher", "team",
    "technology", "television", "tell", "ten", "tend", "term", "test", "than",
    "thank", "that", "the", "their", "them", "themselves", "then", "theory", "there",
    "these", "they", "thing", "think", "third", "this", "those", "though", "thought",
    "thousand", "threat", "three", "through", "throughout", "throw", "thus", "time",
    "to", "today", "together", "tonight", "too", "top", "total", "tough", "toward",
    "town", "trade", "traditional", "training", "travel", "treat", "treatment",
    "tree", "trial", "trip", "trouble", "true", "truth", "try", "turn", "TV", "two",
    "type", "under", "understand", "unit", "until", "up", "upon", "us", "use",
    "usually", "value", "various", "very", "victim", "view", "violence", "visit",
    "voice", "vote", "wait", "walk", "wall", "want", "war", "watch", "water", "way",
    "we", "weapon", "wear", "week", "weight", "well", "west", "western", "what",
    "whatever", "when", "where", "whether", "which", "while", "white", "who",
    "whole", "whom", "whose", "why", "wide", "wife", "will", "win", "wind", "window",
    "wish", "with", "within", "without", "woman", "wonder", "word", "work", "worker",
    "world", "worry", "would", "write", "writer", "wrong", "yard", "yeah", "year",
    "yes", "yet", "you", "young", "your", "yourself", "youth", "about", "above",
    "after", "again", "age", "agree", "air", "all", "also", "am", "among", "animal",
    "another", "answer", "any", "around", "arrive", "art", "as", "ask", "at", "attack",
    "attention", "attorney", "audience", "author", "authority", "available", "avoid",
    "baby", "back", "bad", "bag", "ball", "bar", "base", "be", "beat", "beautiful",
    "because", "become", "bed", "before", "begin", "behavior", "behind", "believe",
    "benefit", "best", "better", "between", "beyond", "big", "bill", "billion", "bit",
    "black", "blood", "blue", "board", "body", "book", "born", "both", "box", "boy",
    "break", "bring", "brother", "budget", "build", "building", "business", "but",
    "buy", "by", "call", "camera", "campaign", "can", "cancer", "candidate", "capital",
    "car", "card", "care", "career", "carry", "case", "catch", "cause", "cell",
    "center", "central", "century", "certain", "certainly", "chair", "challenge",
    "chance", "change", "character", "charge", "check", "child", "choice", "choose",
    "church", "citizen", "city", "civil", "claim", "class", "clean", "clear",
    "clearly", "close", "coach", "cold", "collection", "college", "color", "come",
    "commercial", "common", "community", "company", "compare", "computer", "concern",
    "condition", "conference", "Congress", "consider", "consumer", "contain", "continue",
    "control", "cost", "could", "country", "couple", "course", "court", "cover",
    "create", "crime", "cultural", "culture", "cup", "current", "customer", "cut",
    "dark", "data", "daughter", "day", "dead", "deal", "death", "debate", "decade",
    "decide", "decision", "deep", "defense", "degree", "Democrat", "democratic",
    "describe", "design", "despite", "detail", "determine", "develop", "development",
    "die", "difference", "different", "difficult", "dinner", "direction", "director",
    "discover", "discuss", "discussion", "disease", "do", "doctor", "dog", "door",
    "down", "draw", "dream", "drive", "drop", "drug", "during", "each", "early",
    "east", "easy", "eat", "economic", "economy", "edge", "education", "effect",
    "effort", "eight", "either", "election", "else", "employee", "end", "energy",
    "enjoy", "enough", "enter", "entire", "environment", "environmental", "especially",
    "establish", "even", "evening", "event", "ever", "every", "everybody", "everyone",
    "everything", "evidence", "exactly", "example", "executive", "exist", "expect",
    "experience", "expert", "explain", "eye", "face", "fact", "factor", "fail",
    "fall", "family", "far", "fast", "father", "fear", "federal", "feel", "feeling",
    "few", "field", "fight", "figure", "fill", "film", "final", "finally", "financial",
    "find", "fine", "finger", "finish", "fire", "firm", "first", "fish", "five",
    "floor", "fly", "focus", "follow", "food", "foot", "for", "force", "foreign",
    "forget", "former", "formally", "forward", "four", "free", "friend", "from",
    "front", "full", "fund", "future", "garden", "gas", "general", "generation",
    "get", "girl", "give", "glass", "go", "goal", "god", "good", "government",
    "great", "green", "ground", "group", "grow", "growth", "guess", "gun", "guy",
    "hair", "half", "hand", "hang", "happen", "happy", "hard", "have", "he", "head",
    "health", "hear", "heart", "heat", "heavy", "help", "her", "here", "herself",
    "high", "him", "himself", "his", "history", "hit", "hold", "home", "hope",
    "hospital", "hot", "hotel", "hour", "house", "how", "however", "huge", "human",
    "hundred", "husband", "I", "idea", "identify", "if", "image", "imagine", "impact",
    "important", "improve", "in", "include", "including", "increase", "indeed",
    "indicate", "individual", "industry", "information", "inside", "instead",
    "institution", "interest", "interesting", "international", "interview", "into",
    "investment", "involve", "issue", "it", "item", "its", "itself", "job", "join",
    "just", "keep", "key", "kid", "kill", "kind", "kitchen", "know", "knowledge",
    "land", "language", "large", "last", "late", "later", "laugh", "law", "lay",
    "lead", "leader", "learn", "least", "leave", "left", "leg", "legal", "less",
    "let", "letter", "level", "lie", "life", "light", "like", "likely", "line",
    "list", "listen", "little", "live", "local", "long", "look", "lose", "loss",
    "lot", "love", "low", "machine", "magazine", "main", "maintain", "major",
    "majority", "make", "man", "manage", "management", "manager", "many", "market",
    "marriage", "material", "matter", "may", "maybe", "me", "mean", "measure",
    "media", "medical", "meet", "meeting", "member", "memory", "mention", "message",
    "method", "middle", "might", "military", "million", "mind", "minute", "miss",
    "mission", "model", "modern", "moment", "money", "month", "more", "morning",
    "most", "mother", "mouth", "move", "movement", "movie", "Mrs", "much", "music",
    "must", "my", "myself", "name", "nation", "national", "natural", "nature",
    "near", "nearly", "necessary", "need", "network", "never", "new", "news",
    "newspaper", "next", "nice", "night", "no", "none", "nor", "north", "not",
    "note", "nothing", "notice", "now", "number", "occur", "of", "off", "offer",
    "office", "officer", "official", "often", "oh", "oil", "ok", "old", "on", "once",
    "one", "only", "onto", "open", "operation", "opportunity", "option", "or",
    "order", "organization", "other", "others", "our", "out", "outside", "over",
    "own", "owner", "page", "pain", "painting", "paper", "parent", "part", "participant",
    "particular", "particularly", "partner", "party", "pass", "past", "patient",
    "pattern", "pay", "peace", "people", "per", "perform", "performance", "perhaps",
    "period", "person", "personal", "phone", "physical", "pick", "picture", "piece",
    "place", "plan", "plant", "play", "player", "PM", "point", "police", "policy",
    "political", "politics", "poor", "popular", "population", "position", "positive",
    "possible", "power", "practice", "prepare", "present", "president", "pressure",
    "pretty", "prevent", "price", "private", "probably", "problem", "process", "produce",
    "product", "production", "professional", "professor", "program", "project", "property",
    "protect", "prove", "provide", "public", "pull", "purpose", "push", "put", "quality",
    "question", "quickly", "quite", "race", "radio", "raise", "range", "rate", "rather",
    "reach", "read", "ready", "real", "reality", "realize", "really", "reason", "receive",
    "recent", "recently", "recognize", "record", "red", "reduce", "reflect", "region",
    "relate", "relationship", "religious", "remain", "remember", "remove", "report",
    "represent", "Republican", "require", "research", "resource", "respond",
    "response", "rest", "result", "return", "reveal", "rich", "right", "rise",
    "risk", "road", "rock", "role", "room", "rule", "run", "safe", "same", "save",
    "say", "scene", "school", "science", "scientist", "score", "sea", "season",
    "seat", "second", "section", "security", "see", "seek", "seem", "sell", "send",
    "senior", "sense", "series", "serious", "serve", "service", "set", "seven",
    "several", "shake", "shall", "shape", "share", "she", "shoot", "shop", "short",
    "shot", "should", "shoulder", "show", "side", "sign", "significant", "similar",
    "simple", "simply", "since", "sing", "single", "sister", "sit", "site", "situation",
    "six", "size", "skill", "skin", "small", "smile", "so", "social", "society",
    "soldier", "some", "somebody", "someone", "something", "sometimes", "son", "song",
    "soon", "sort", "sound", "source", "south", "southern", "space", "speak", "special",
    "specific", "speech", "spend", "sport", "spring", "staff", "stage", "stand",
    "standard", "star", "start", "state", "statement", "station", "stay", "step",
    "still", "stock", "stop", "store", "story", "strategy", "street", "strong",
    "structure", "student", "study", "stuff", "style", "subject", "success", "successful",
    "such", "suddenly", "suffer", "suggest", "summer", "support", "sure", "surface",
    "system", "table", "take", "talk", "task", "tax", "teach", "teacher", "team",
    "technology", "television", "tell", "ten", "tend", "term", "test", "than",
    "thank", "that", "the", "their", "them", "themselves", "then", "theory", "there",
    "these", "they", "thing", "think", "third", "this", "those", "though", "thought",
    "thousand", "threat", "three", "through", "throughout", "throw", "thus", "time",
    "to", "today", "together", "tonight", "too", "top", "total", "tough", "toward",
    "town", "trade", "traditional", "training", "travel", "treat", "treatment",
    "tree", "trial", "trip", "trouble", "true", "truth", "try", "turn", "TV", "two",
    "type", "under", "understand", "unit", "until", "up", "upon", "us", "use",
    "usually", "value", "various", "very", "victim", "view", "violence", "visit",
    "voice", "vote", "wait", "walk", "wall", "want", "war", "watch", "water", "way",
    "we", "weapon", "wear", "week", "weight", "well", "west", "western", "what",
    "whatever", "when", "where", "whether", "which", "while", "white", "who",
    "whole", "whom", "whose", "why", "wide", "wife", "will", "win", "wind", "window",
    "wish", "with", "within", "without", "woman", "wonder", "word", "work", "worker",
    "world", "worry", "would", "write", "writer", "wrong", "yard", "yeah", "year",
    "yes", "yet", "you", "young", "your", "yourself", "youth"
]

SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"

def generate_passphrase(args):
    wordlist = WORDLIST
    word_count = args.words
    separator = args.separator
    entropy = math.log2(len(wordlist)) * word_count

    words = [secrets.choice(wordlist) for _ in range(word_count)]
    result = separator.join(words)

    if args.capitalize:
        result = result[0].upper() + result[1:]
        entropy += 1

    if args.digit:
        digit = str(secrets.randbelow(10))
        result += digit
        entropy += math.log2(10)

    return result, entropy

def generate_password(args):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + SYMBOLS
    length = args.length
    entropy = math.log2(len(charset)) * length

    password = ''.join(secrets.choice(charset) for _ in range(length))
    return password, entropy

def main():
    parser = argparse.ArgumentParser(
        description="Generate secure passphrases and passwords.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="mode", help="Generation mode")

    # Passphrase mode (default)
    passphrase_parser = subparsers.add_parser("passphrase", help="Generate a passphrase")
    passphrase_parser.add_argument("--words", "-w", type=int, default=4,
                                   help="Number of words (default: 4)")
    passphrase_parser.add_argument("--separator", "-s", default="-",
                                   help="Separator between words (default: '-')")
    passphrase_parser.add_argument("--capitalize", "-c", action="store_true",
                                   help="Capitalize first character")
    passphrase_parser.add_argument("--digit", "-d", action="store_true",
                                   help="Append a random digit")
    passphrase_parser.add_argument("--count", "-n", type=int, default=1,
                                   help="Number of passphrases to generate (default: 1)")

    # Password mode
    password_parser = subparsers.add_parser("password", help="Generate a password")
    password_parser.add_argument("--length", "-l", type=int, default=20,
                                 help="Password length (default: 20)")
    password_parser.add_argument("--count", "-n", type=int, default=1,
                                 help="Number of passwords to generate (default: 1)")

    parser.set_defaults(words=4, separator="-", capitalize=False,
                        digit=False, count=1, length=20)
    args = parser.parse_args()

    if args.mode is None:
        args.mode = "passphrase"

    if args.mode == "passphrase":
        if args.words < 1:
            print("Error: --words must be at least 1", file=sys.stderr)
            sys.exit(1)
        if args.count < 1:
            print("Error: --count must be at least 1", file=sys.stderr)
            sys.exit(1)
        for _ in range(args.count):
            secret, entropy = generate_passphrase(args)
            print(f"{secret} (entropy: {entropy:.2f} bits)")
    elif args.mode == "password":
        if args.length < 1:
            print("Error: --length must be at least 1", file=sys.stderr)
            sys.exit(1)
        if args.count < 1:
            print("Error: --count must be at least 1", file=sys.stderr)
            sys.exit(1)
        for _ in range(args.count):
            secret, entropy = generate_password(args)
            print(f"{secret} (entropy: {entropy:.2f} bits)")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
