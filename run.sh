cd etc
./genkeys.sh my
./genkeys.sh other
cd ..
mvn compile
mvn exec:java -e -Dexec.mainClass=edu.stanford.mobisocial.bumblebee.Main -Dexec.args="${1} ${2}" 
