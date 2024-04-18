void main() {
        print("Hello Radare2" + r2cmd("pd 10"));
        print("FileName: " + r2cmdj("ij")["core"]["file"]);
}
