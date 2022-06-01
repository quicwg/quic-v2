TARGETS_DRAFTS := draft-duke-quic-v2 
TARGETS_TAGS := 
draft-duke-quic-v2-00.md: draft-duke-quic-v2.md
	sed -e 's/draft-duke-quic-v2-latest/draft-duke-quic-v2-00/g' $< >$@
