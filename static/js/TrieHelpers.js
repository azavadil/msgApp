


function buildTrie(nameList){
	var trie = new TrieST(); 
	for (name in nameList){ 
		trie.put(name.trim(), 1); 
	}
	return trie; 
}