"""LLM agents (the *recommenders*) and the provider abstraction beneath them.

Agents here are deliberately naive: they model the documented failure mode of a
back-office LLM that treats every span in its context as potentially
instructional. Their output is typed ``MODEL_GENERATED`` and is never
authoritative."""
