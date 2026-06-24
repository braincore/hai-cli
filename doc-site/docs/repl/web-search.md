# Web search

!!! warning "Experimental"
    Web search is experimental and may change in future releases.

Web search helps you bring context into the LLM for current events and areas
that are beyond its base knowledge. It's built on top of the
[Brave Search API](https://brave.com/search/api/).

## Search basics

To search manually, use:

```
/web-search <query>
/web-search.pd <query>  # past day
/web-search.pw <query>  # past week
/web-search.pm <query>  # past month
/web-search.py <query>  # past year
/web-search.range="2026-01-01to2026-01-31" <query>  # range
/web-search.n=3 <query>  # return 3 results max
```

## Searching with the LLM

Using the [`!hai` tool](./tools.md#hai-tool-hai), when asking the LLM a
question, it can decide whether to invoke the `/web-search` command as well as
summarize the answer for you either through [recursion](./tools.md#hai-recursion)
or [agentic mode](./tools.md#agentic-mode).

```
[0] !hai When is the next San Jose Sharks game?
```
