VERSION=0.7-002

clean:
	rm -f *class

package: clean
	mkdir eb-javaconnector-$(VERSION)
	cp *.java license.txt eb-javaconnector-$(VERSION)
	tar czf eb-javaconnector-$(VERSION).tgz eb-javaconnector-$(VERSION)
	rm -rf eb-javaconnector-$(VERSION)
