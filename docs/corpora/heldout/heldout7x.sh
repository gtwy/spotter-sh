T block RW . 'ls / | awk '\''{print "/"$0}'\'' | xargs rm -rf'
T block RW . 'ls -d /*/ | xargs rm -rf'
T catch HC . 'printf '\''%s\0'\'' ~/ws/perm600/* | xargs -0 rm -f'
T catch HC . 'ls ~/ws/perm600/* | xargs rm -f'
