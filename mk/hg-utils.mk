hg-miss:
	@-hg st . | grep -e vala$$ | grep ^?
	@-hg st . | grep -e \\.c$$ | grep -v vapi | grep ^?
	@true
