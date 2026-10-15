# carcc.github.io

The CaRCC organization's GitHub Pages site, served at <https://carcc.github.io/>.
It is a plain HTML/CSS link page plus short-URL aliases for CaRCC project sites.

## Aliases

- <https://carcc.github.io/ai-handbook/> →
  <https://carcc.github.io/CaRCC-AI-Facilitation-Handbook/>

An alias needs two pieces:

1. `<alias>/index.html`: a redirect stub, so the alias root returns 200
   (copy `ai-handbook/index.html` and change the two names).
2. An entry in the `aliases` map in `404.html`, which forwards deep links
   (`/<alias>/any/page`) to the same path on the target site.

A repo with Pages enabled always takes its own path, so an alias can't reuse
the name of such a repo.

## Publishing

GitHub Pages deploys from the `main` branch root. `.nojekyll` turns off Jekyll
processing. There is no build step.
