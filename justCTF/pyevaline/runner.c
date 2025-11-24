#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int _, char** a, char** envp) {
	// Omg such secure!
	unsetenv("PYTHONPATH");
	unsetenv("PYTHONHOME");
	unsetenv("PYTHONSTARTUP");
	unsetenv("PYTHONBREAKPOINT");
	unsetenv("PYTHONUSERBASE");
	unsetenv("PYTHONEXECUTABLE");

	char* argv[] = {
		"python3",
		"-E", "-I", "-s",  // Double, or triple secure!
		"/home/ctfplayer/app",
		NULL
	};

	execve("/usr/local/bin/python3", argv, envp);
}
