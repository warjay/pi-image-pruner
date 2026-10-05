# pi-image-pruner

Keeps only the N most recent images (`keepLast`, default 6) in the outgoing
LLM request and replaces older image blocks with a text placeholder. Makes
image-driven context/request-body overflow impossible regardless of whether
the provider counts image tokens. Session history keeps all images.

Also sanitizes image formats the provider cannot decode: images copy-pasted
from webpages are often AVIF/WEBP (sniffed from magic bytes, not the declared
mimeType), and Ollama's Go backend rejects them with 400 "invalid image
input" (cf. ollama/ollama #11410). Undecodable images are replaced with an
explanatory note; blocks with a wrong mimeType but decodable bytes are fixed
in place. Configure via `sanitizeImages` and `allowedImageFormats`.

Config: image-pruner.config.json in this directory; optional per-project
override at <cwd>/.pi/image-pruner.json.