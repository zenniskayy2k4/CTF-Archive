An example communication script has been added for your convenience. You can start editing `solver/solver.c` to implement your solution.

The `no-net` binary prevents the processes from making any networking related syscalls.  
The `landrun` config restricts filesystem access. Read more about `land{run,lock}` here: https://github.com/Zouuup/landrun. (And see the forked commit here: https://github.com/Victor4X/landrun/commit/1923a96)

Happy hacking!

*Note:* If you get an error saying "... missing kernel Landlock support ...", your kernel is too old to run the challenge locally.
The challenge uses a fork with lower Landlock ABI requirements, which should be included in kernels after 5.13 (released 27th of June 2021).
