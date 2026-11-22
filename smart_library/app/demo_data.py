"""Extended demo catalogue and demo circulation history.

Safe to rerun: books and members are inserted with INSERT OR IGNORE, metadata is only
filled where it is still empty, and circulation history is written once (guarded by an
``app_meta`` marker). Nothing that already exists is overwritten.

Run manually with:  python -m app.demo_data   (uses SLMS_DB_PATH)
Disable at start-up with SLMS_DEMO_DATA=0.

Digital editions are either public-domain text (opening passages of classic works) or
original study material written for this demo. No copyrighted text is included.
"""
from __future__ import annotations

import random
import time

from .db import Database

DAY = 86400.0

EXTRA_MEMBERS = [
    ("m-erin", "Erin", "erin@library.example", ["students"]),
    ("m-farid", "Farid", "farid@library.example", ["students"]),
    ("m-grace", "Grace", "grace@library.example", ["faculty"]),
    ("m-hiro", "Hiro", "hiro@library.example", ["students"]),
]

# --- digital editions --------------------------------------------------------------------
FRANKENSTEIN = """## Letter 1
To Mrs. Saville, England. St. Petersburgh, Dec. 11th, 17—.

You will rejoice to hear that no disaster has accompanied the commencement of an enterprise which you have regarded with such evil forebodings. I arrived here yesterday, and my first task is to assure my dear sister of my welfare and increasing confidence in the success of my undertaking.

I am already far north of London, and as I walk in the streets of Petersburgh, I feel a cold northern breeze play upon my cheeks, which braces my nerves and fills me with delight. Do you understand this feeling? This breeze, which has travelled from the regions towards which I am advancing, gives me a foretaste of those icy climes.

## About this edition
Mary Shelley's novel was first published in 1818 and is in the public domain. This digital edition contains the opening passage for demonstration purposes."""

TWO_CITIES = """## Book the First — Recalled to Life
It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way—in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only.

There were a king with a large jaw and a queen with a plain face, on the throne of England; there were a king with a large jaw and a queen with a fair face, on the throne of France. In both countries it was clearer than crystal to the lords of the State preserves of loaves and fishes, that things in general were settled for ever.

## About this edition
Charles Dickens' novel (1859) is in the public domain. This digital edition contains the opening passage."""

MOBY_DICK = """## Chapter 1 — Loomings
Call me Ishmael. Some years ago—never mind how long precisely—having little or no money in my purse, and nothing particular to interest me on shore, I thought I would sail about a little and see the watery part of the world. It is a way I have of driving off the spleen and regulating the circulation.

Whenever I find myself growing grim about the mouth; whenever it is a damp, drizzly November in my soul; whenever I find myself involuntarily pausing before coffin warehouses, and bringing up the rear of every funeral I meet; and especially whenever my hypos get such an upper hand of me, that it requires a strong moral principle to prevent me from deliberately stepping into the street, and methodically knocking people's hats off—then, I account it high time to get to sea as soon as I can. This is my substitute for pistol and ball.

## About this edition
Herman Melville's novel (1851) is in the public domain. This digital edition contains the opening passage."""

ART_OF_WAR = """## Chapter I — Laying Plans
Sun Tzu said: The art of war is of vital importance to the State.

It is a matter of life and death, a road either to safety or to ruin. Hence it is a subject of inquiry which can on no account be neglected.

The art of war, then, is governed by five constant factors, to be taken into account in one's deliberations, when seeking to determine the conditions obtaining in the field.

These are: (1) The Moral Law; (2) Heaven; (3) Earth; (4) The Commander; (5) Method and discipline.

## The five factors
The Moral Law causes the people to be in complete accord with their ruler, so that they will follow him regardless of their lives, undismayed by any danger.

Heaven signifies night and day, cold and heat, times and seasons.

Earth comprises distances, great and small; danger and security; open ground and narrow passes; the chances of life and death.

## About this edition
Lionel Giles' 1910 English translation is in the public domain. This digital edition contains part of the first chapter."""

WEALTH_OF_NATIONS = """## Book I, Chapter I — Of the Division of Labour
The greatest improvement in the productive powers of labour, and the greatest part of the skill, dexterity, and judgment with which it is anywhere directed, or applied, seem to have been the effects of the division of labour.

The effects of the division of labour, in the general business of society, will be more easily understood by considering in what manner it operates in some particular manufactures.

## About this edition
Adam Smith's work (1776) is in the public domain. This digital edition contains the opening passage."""

ORIGIN_OF_SPECIES = """## Introduction
When on board H.M.S. 'Beagle,' as naturalist, I was much struck with certain facts in the distribution of the inhabitants of South America, and in the geological relations of the present to the past inhabitants of that continent. These facts seemed to me to throw some light on the origin of species—that mystery of mysteries, as it has been called by one of our greatest philosophers.

## About this edition
Charles Darwin's work (1859) is in the public domain. This digital edition contains the opening passage."""

HANDBOOK = """## Welcome
The Smart Library Handbook explains how the library works for members. It is original demo material written for this project.

Every member signs in with a verified identity. The library never accepts an email address on its own as proof of who you are: each request carries a signed token issued by the identity service.

## Finding books
Use the catalogue to search by title, author, ISBN or category. You only see titles from collections you are allowed to use. If a title belongs to a restricted collection, such as finance reports or HR policies, it is not shown to members outside that group, and looking it up directly gives the same answer as a book that does not exist.

## Borrowing and returning
A standard loan lasts 14 days and you may hold up to 5 loans at a time. You cannot borrow new items while one of your loans is overdue. Late returns are fined 0.50 per day, rounded up to whole days.

You can renew a loan for another 14 days unless another member is waiting for the title.

## Reservations
When every copy is on loan you can join the reservation queue. Queues are first come, first served. When a copy is returned it is placed on the hold shelf for the first member in the queue, and nobody else can borrow it.

## Why access is checked twice
The library checks your access when it shows you a title and again at the moment you borrow, reserve, renew or open it. If your access was removed in between, the second check refuses the request. If the library cannot verify your access at all, it refuses rather than guessing."""

ML_NOTES = """## 1. What is machine learning?
These study notes are original demo material written for the Smart Library project.

Machine learning is the study of programs that improve at a task through experience. Instead of writing every rule by hand, we choose a family of models and let data select the parameters.

## 2. Supervised learning
In supervised learning each training example has an input and a known label. Regression predicts a number, such as a house price; classification predicts a category, such as spam or not spam. A model is trained by minimising a loss function that measures how far its predictions are from the labels.

## 3. Generalisation
A model that memorises its training data can fail on new data. This is called overfitting. We estimate real performance on a held-out test set, and use validation data or cross-validation to choose hyper-parameters. Regularisation, more data and simpler models all reduce overfitting.

## 4. Unsupervised learning
Without labels we can still find structure. Clustering groups similar examples together; dimensionality reduction, such as principal component analysis, finds a smaller set of features that keeps most of the variation.

## 5. Evaluating a classifier
Accuracy alone can mislead when classes are imbalanced. Precision measures how many predicted positives are correct; recall measures how many real positives were found. The F1 score combines both."""

# id, isbn, title, author, category, year, collection, copies, digital, description, added_days_ago
EXTRA_BOOKS = [
    ("b-013", "9780134610993", "Artificial Intelligence: A Modern Approach", "Stuart Russell & Peter Norvig",
     "Artificial Intelligence", 2020, "general", 3, None,
     "The standard university introduction to AI: search, knowledge representation, planning, probabilistic "
     "reasoning, machine learning and the ethics of intelligent systems.", 2),
    ("b-014", "9780262035613", "Deep Learning", "Ian Goodfellow, Yoshua Bengio & Aaron Courville",
     "Machine Learning", 2016, "research", 2, None,
     "A rigorous treatment of deep neural networks, from linear algebra and optimisation to convolutional, "
     "recurrent and generative models.", 5),
    ("b-015", "9780387310732", "Pattern Recognition and Machine Learning", "Christopher M. Bishop",
     "Machine Learning", 2006, "research", 1, None,
     "A Bayesian perspective on machine learning covering graphical models, kernel methods, mixture models "
     "and approximate inference.", 40),
    ("b-016", "9781492032649", "Hands-On Machine Learning with Scikit-Learn, Keras, and TensorFlow",
     "Aurélien Géron", "Machine Learning", 2019, "general", 2, None,
     "A practical, project-driven guide to building machine learning systems with Python's most popular "
     "libraries.", 9),
    ("b-017", "9780262039246", "Reinforcement Learning: An Introduction", "Richard S. Sutton & Andrew G. Barto",
     "Artificial Intelligence", 2018, "research", 1, None,
     "The foundational text on agents that learn from reward: bandits, dynamic programming, temporal-difference "
     "learning and policy gradients.", 21),
    ("b-018", "9780980232776", "Introduction to Linear Algebra", "Gilbert Strang", "Mathematics", 2016,
     "general", 2, None,
     "Vectors, matrices, elimination, vector spaces, eigenvalues and the singular value decomposition, taught "
     "with an emphasis on understanding.", 30),
    ("b-019", "9780538497817", "Calculus: Early Transcendentals", "James Stewart", "Mathematics", 2012,
     "general", 3, None,
     "Limits, derivatives, integrals, series and multivariable calculus with thousands of worked examples and "
     "exercises.", 60),
    ("b-020", "9780201558029", "Concrete Mathematics", "Ronald L. Graham, Donald E. Knuth & Oren Patashnik",
     "Mathematics", 1994, "general", 1, None,
     "The mathematics behind computer science: sums, recurrences, number theory, binomial coefficients and "
     "generating functions.", 45),
    ("b-021", "9780465024933", "The Feynman Lectures on Physics, Vol. I", "Richard P. Feynman", "Physics", 2011,
     "general", 2, None,
     "Feynman's celebrated undergraduate lectures on mechanics, radiation and heat.", 14),
    ("b-022", "9781108420419", "Introduction to Electrodynamics", "David J. Griffiths", "Physics", 2017,
     "general", 2, None,
     "A clear, student-friendly course in electrostatics, magnetostatics, Maxwell's equations and "
     "electromagnetic waves.", 33),
    ("b-023", "9780451524935", "Nineteen Eighty-Four", "George Orwell", "Literature", 1949, "general", 1, None,
     "Orwell's dystopian novel of surveillance, propaganda and the struggle to think freely.", 50),
    ("b-024", "9780060883287", "One Hundred Years of Solitude", "Gabriel García Márquez", "Literature", 1967,
     "general", 2, None,
     "The multi-generational story of the Buendía family and the town of Macondo.", 27),
    ("b-025", "9780486282114", "Frankenstein", "Mary Shelley", "Literature", 1818, "general", 2, FRANKENSTEIN,
     "Victor Frankenstein's creation and its consequences — the founding work of science fiction. "
     "Public-domain digital edition available.", 1),
    ("b-026", "9780486406510", "A Tale of Two Cities", "Charles Dickens", "Literature", 1859, "general", 2,
     TWO_CITIES, "London and Paris before and during the French Revolution. Public-domain digital edition "
     "available.", 12),
    ("b-027", "9780142437247", "Moby-Dick", "Herman Melville", "Literature", 1851, "general", 1, MOBY_DICK,
     "Captain Ahab's obsessive hunt for the white whale. Public-domain digital edition available.", 18),
    ("b-028", "9780393317558", "Guns, Germs, and Steel", "Jared Diamond", "History", 1997, "general", 2, None,
     "Why did some societies come to dominate others? A sweeping account of geography, food production and "
     "technology in human history.", 36),
    ("b-029", "9780062316097", "Sapiens: A Brief History of Humankind", "Yuval Noah Harari", "History", 2015,
     "general", 3, None,
     "From the cognitive revolution to the present: how Homo sapiens came to rule the planet.", 7),
    ("b-030", "9781599869773", "The Art of War", "Sun Tzu (trans. Lionel Giles)", "History", 1910, "general", 2,
     ART_OF_WAR, "The classic treatise on strategy, in Lionel Giles' public-domain translation.", 25),
    ("b-031", "9780374533557", "Thinking, Fast and Slow", "Daniel Kahneman", "Business", 2011, "general", 2, None,
     "How two systems of thought shape our judgements and decisions, and where they lead us astray.", 3),
    ("b-032", "9780307887894", "The Lean Startup", "Eric Ries", "Business", 2011, "general", 2, None,
     "Build, measure, learn: a method for developing products and businesses under uncertainty.", 16),
    ("b-033", "9780553585971", "The Wealth of Nations", "Adam Smith", "Business", 1776, "general", 1,
     WEALTH_OF_NATIONS, "The founding work of modern economics. Public-domain digital edition available.", 55),
    ("b-034", "9780465050659", "The Design of Everyday Things", "Don Norman", "Engineering", 2013, "general", 2,
     None, "Why some products satisfy and others frustrate: the principles of human-centred design.", 11),
    ("b-035", "9780306812835", "Structures: Or Why Things Don't Fall Down", "J. E. Gordon", "Engineering", 1978,
     "general", 1, None, "An accessible explanation of how bridges, buildings, aircraft and living things carry "
     "loads.", 42),
    ("b-036", "9780262510875", "Structure and Interpretation of Computer Programs",
     "Harold Abelson & Gerald Jay Sussman", "Computer Science", 1996, "general", 2, None,
     "Abstraction, recursion, interpreters and the design of programs, from MIT's classic introductory "
     "course.", 38),
    ("b-037", "9780135957059", "The Pragmatic Programmer", "David Thomas & Andrew Hunt", "Computer Science", 2019,
     "general", 2, None, "Practical advice for writing flexible, maintainable software and growing as a "
     "developer.", 4),
    ("b-038", "9780140432053", "On the Origin of Species", "Charles Darwin", "Science", 1859, "general", 1,
     ORIGIN_OF_SPECIES, "Darwin's theory of evolution by natural selection. Public-domain digital edition "
     "available.", 29),
    ("b-039", "SL-HANDBOOK-1", "The Smart Library Handbook", "Smart Library Editorial", "Reference", 2026,
     "general", 1, HANDBOOK, "Everything members need to know about searching, borrowing, reservations and "
     "how access is protected. Original demo content.", 0),
    ("b-040", "SL-MLNOTES-1", "Machine Learning: Study Notes", "Smart Library Editorial", "Machine Learning", 2026,
     "research", 1, ML_NOTES, "Concise study notes on supervised and unsupervised learning and model "
     "evaluation. Original demo content for research members.", 6),
]

# Descriptions for the original 12 titles (filled only where still empty).
BASE_DESCRIPTIONS = {
    "b-001": "The comprehensive reference on algorithms and data structures: sorting, graphs, dynamic "
             "programming and complexity.",
    "b-002": "A handbook of agile software craftsmanship: naming, functions, error handling and refactoring.",
    "b-003": "Elizabeth Bennet and Mr. Darcy in Austen's sharp comedy of manners.",
    "b-004": "A story of justice and childhood in the American South.",
    "b-005": "Hawking's accessible journey from the Big Bang to black holes.",
    "b-006": "The big ideas behind reliable, scalable and maintainable data systems.",
    "b-007": "Peer-reviewed research on library systems and automation. Research members only.",
    "b-008": "Confidential finance forecast. Restricted to the Finance department.",
    "b-009": "Next year's library budget. Restricted to the Finance department.",
    "b-010": "Confidential personnel policy. Restricted to Human Resources.",
    "b-011": "Facsimile of the 1623 First Folio. Reading room only, by individual grant.",
    "b-012": "A fast-paced thriller of codes, art history and secret societies.",
}


def _meta(db: Database, key: str) -> str | None:
    row = db.one("SELECT value FROM app_meta WHERE key = ?", (key,))
    return row["value"] if row else None


def load_demo_data(db: Database, now: float | None = None) -> bool:
    """Load the extended demo data. Returns True if anything affecting access policy changed."""
    now = now if now is not None else time.time()
    policy_changed = False
    with db.tx() as c:
        for mid, name, email, groups in EXTRA_MEMBERS:
            cur = c.execute("INSERT OR IGNORE INTO members (id, name, email) VALUES (?, ?, ?)", (mid, name, email))
            if cur.rowcount:
                policy_changed = True
                for g in groups:
                    c.execute("INSERT OR IGNORE INTO memberships (member_id, group_id) VALUES (?, ?)", (mid, g))
        for (bid, isbn, title, author, cat, year, col, copies, digital, desc, days) in EXTRA_BOOKS:
            c.execute(
                "INSERT OR IGNORE INTO books (id, isbn, title, author, category, year, collection_id, copies_total,"
                " copies_available, digital_content, description, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (bid, isbn, title, author, cat, year, col, copies, copies, digital, desc, now - days * DAY))
        for bid, desc in BASE_DESCRIPTIONS.items():
            c.execute("UPDATE books SET description = ? WHERE id = ? AND description = ''", (desc, bid))
        # Books without an "added" date get one from the original catalogue load.
        c.execute("UPDATE books SET added_at = ? WHERE added_at IS NULL", (now - 90 * DAY,))
    if _meta(db, "demo_activity_v1") is None:
        _load_activity(db, now)
    return policy_changed


def _load_activity(db: Database, now: float) -> None:
    """Six months of circulation history plus the live demo scenarios. Written once."""
    rng = random.Random(42)
    # Member -> titles they may use (consistent with the seeded access policy).
    general = [r["id"] for r in db.query("SELECT id FROM books WHERE collection_id = 'general'")]
    research = [r["id"] for r in db.query("SELECT id FROM books WHERE collection_id = 'research'")]
    readers = {
        "m-bob": general + research, "m-grace": general + research, "m-dave": general + research,
        "m-erin": general + research, "m-farid": general + research, "m-hiro": general + research,
        "m-alice": general, "m-carol": general,
    }
    readers = {m: b for m, b in readers.items() if db.one("SELECT 1 FROM members WHERE id = ?", (m,))}
    with db.tx() as c:
        # Returned loans spread over the last ~180 days (they do not affect current stock).
        for _ in range(64):
            member = rng.choice(sorted(readers))
            book = rng.choice(readers[member])
            borrowed = now - rng.uniform(20, 180) * DAY
            due = borrowed + 14 * DAY
            late_days = rng.randint(1, 6) if rng.random() < 0.18 else 0
            returned = due + late_days * DAY if late_days else borrowed + rng.uniform(2, 13) * DAY
            fine = round(late_days * 0.5, 2)
            c.execute("INSERT INTO loans (book_id, member_id, borrowed_at, due_at, returned_at, fine)"
                      " VALUES (?, ?, ?, ?, ?, ?)", (book, member, borrowed, due, returned, fine))
        # Live scenarios: (member, book, borrowed days ago).
        scenarios = [
            ("m-alice", "b-013", 12),   # due in 2 days -> "due soon"
            ("m-alice", "b-031", 4),
            ("m-bob", "b-023", 5),      # the only copy -> Dave reserves it below
            ("m-carol", "b-002", 20),   # overdue by 6 days -> fine accruing
            ("m-dave", "b-018", 3),
            ("m-grace", "b-014", 8),
            ("m-erin", "b-029", 1),
        ]
        for member, book, ago in scenarios:
            if member not in readers:
                continue
            active = c.execute("SELECT COUNT(*) FROM loans WHERE member_id = ? AND returned_at IS NULL",
                               (member,)).fetchone()[0]
            dup = c.execute("SELECT 1 FROM loans WHERE member_id = ? AND book_id = ? AND returned_at IS NULL",
                            (member, book)).fetchone()
            if active >= 5 or dup:
                continue
            cur = c.execute("UPDATE books SET copies_available = copies_available - 1"
                            " WHERE id = ? AND copies_available > 0", (book,))
            if cur.rowcount:
                borrowed = now - ago * DAY
                c.execute("INSERT INTO loans (book_id, member_id, borrowed_at, due_at) VALUES (?, ?, ?, ?)",
                          (book, member, borrowed, borrowed + 14 * DAY))
        # Dave waits for Nineteen Eighty-Four (Bob holds the only copy).
        held = c.execute("SELECT copies_available FROM books WHERE id = 'b-023'").fetchone()
        if held is not None and held[0] == 0 and not c.execute(
                "SELECT 1 FROM reservations WHERE book_id = 'b-023' AND member_id = 'm-dave'"
                " AND status IN ('waiting','ready')").fetchone():
            c.execute("INSERT INTO reservations (book_id, member_id, created_at, status, updated_at)"
                      " VALUES ('b-023', 'm-dave', ?, 'waiting', ?)", (now - 2 * DAY, now - 2 * DAY))
        # A little reservation history for the trend chart.
        for _ in range(14):
            member = rng.choice(sorted(readers))
            book = rng.choice(readers[member])
            at = now - rng.uniform(15, 170) * DAY
            status = rng.choice(["fulfilled", "fulfilled", "cancelled"])
            c.execute("INSERT INTO reservations (book_id, member_id, created_at, status, updated_at)"
                      " VALUES (?, ?, ?, ?, ?)", (book, member, at, status, at + 5 * DAY))
        c.execute("INSERT INTO app_meta (key, value) VALUES ('demo_activity_v1', ?)", (str(now),))
        c.execute("INSERT INTO audit_log (at, member_id, action, resource, decision, reason, policy_revision)"
                  " VALUES (?, NULL, 'demo_data', NULL, 'info', 'demo catalogue and circulation history loaded', NULL)",
                  (now,))


if __name__ == "__main__":  # pragma: no cover
    from .config import Settings
    from .seed import seed

    database = Database(Settings().db_path)
    seed(database)
    load_demo_data(database)
    print("Demo data loaded into", Settings().db_path)
