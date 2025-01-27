#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include "ecdsa.h"

#define WELCOME_MENU \
	"Welcome to Future Desk Market!\n"
#define MAIN_MENU \
	"FDM / Main menu\n\n"\
	"  1) Login\n"\
	"  2) Exit\n"
#define MARKET_MENU \
	"\nFDM / Market menu\n\n"\
	"  1) Put a desk for sale\n" \
	"  2) Sign your listings\n" \
	"  3) Remove a listing (FDM GOLD users only)\n" \
	"  4) Obtain desks for sale list\n" \
	"  5) Check sale authenticity\n" \
	"  6) Acquire FDM GOLD subscription\n" \
	"  7) Logout\n" \
	"  8) Exit\n"
#define BETA_INSERTION_MENU \
	"\nFDM GOLD (BETA) Ad insertion menu\n\n"\
	"  1) Insert data\n" \
	"  2) Preview Ad\n" \
	"  3) Confirm insertion\n" \
	"  4) Discard insertion\n"
#define INVALID_OPTION "Invalid menu option picked! Try again."
#define KEY_FORMAT_INVALID "The key is in an invalid format!\nPlease send your key in the following format: x, y"
#define KEY_NOT_IN_CURVE "The key is not a valid point of the curve!"
#define SIGNATURE_FORMAT_INVALID "The signature is in an invalid format!\nPlease send your signature in the following format: r, s"
#define SIGNATURE_INVALID "The signature could not be verified correctly"
#define LISTING_SEPARATOR "----------------------------------------------"
#define ECDSA_KEY_LEN 1024
#define N_BITS 256
#define MAX_LISTINGS 4096
#define ADMIN_LISTINGS_COUNT 40
#define DESK_NAME_LEN 32
#define DESK_DESCRIPTION_LEN 256
#define ADMIN_TEMPLATES_COUNT 50
#define AUTH_OTP_LEN 32
#define COLORS_COUNT 7

// colors definition
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
char* colors_keys[COLORS_COUNT] = {
	"$RED",
	"$GREEN",
	"$YELLOW",
	"$BLUE",
	"$MAGENTA",
	"$CYAN",
	"$RESET"
};
char* colors_values[COLORS_COUNT] = {
	ANSI_COLOR_RED,
	ANSI_COLOR_GREEN,
	ANSI_COLOR_YELLOW,
	ANSI_COLOR_BLUE,
	ANSI_COLOR_MAGENTA,
	ANSI_COLOR_CYAN,
	ANSI_COLOR_RESET
};
// end colors definition


__attribute__((constructor))
void init() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

typedef struct {
	float depth, width, height;
} desk_sizeT;

typedef struct {
	char name[DESK_NAME_LEN], description[DESK_DESCRIPTION_LEN];
	mpz_t r, s; // listing signature (N_BITS bits long each)
	Point* poster_pubkey;
} desk_listing_infoT;

typedef struct desk_listingT desk_listingT;
struct desk_listingT {
	desk_listingT* next;
	desk_listing_infoT* info;
	desk_sizeT size;
	float price;
	bool is_signed;
};

typedef struct hashable_deskT hashable_deskT;
struct hashable_deskT {
	char name[DESK_NAME_LEN], description[DESK_DESCRIPTION_LEN];
	desk_sizeT size;
};

int urandom_fd;
desk_listingT* listings = NULL;
size_t listings_count = 0;

Curve P256;
Point O, G;

Point admin_Q;
Point user_Q;

char admin_desks_names[ADMIN_TEMPLATES_COUNT][DESK_NAME_LEN] = {
	"Workstation Desk",
	"Executive Desk",
	"Writing Desk",
	"Computer Desk",
	"Standing Desk",
	"L-Shaped Desk",
	"U-Shaped Desk",
	"Corner Desk",
	"Roll-Top Desk",
	"Floating Desk",
	"Adjustable Desk",
	"Secretary Desk",
	"Compact Desk",
	"Desk with Hutch",
	"Glass Desk",
	"Wooden Desk",
	"Minimalist Desk",
	"Foldable Desk",
	"Student Desk",
	"Gaming Desk",
	"Craft Desk",
	"Trestle Desk",
	"Wall-Mounted Desk",
	"Partner Desk",
	"Reception Desk",
	"Modular Desk",
	"Drafting Desk",
	"Vanity Desk",
	"Industrial Desk",
	"Rustic Desk",
	"Mid-Century Desk",
	"Ergonomic Desk",
	"Convertible Desk",
	"Floating Shelf Desk",
	"Laptop Desk",
	"Adjustable Height Desk",
	"Open Frame Desk",
	"Hidden Storage Desk",
	"Double-Sided Desk",
	"Designer Desk",
	"Children's Desk",
	"Media Desk",
	"Convertible Table Desk",
	"Retro Desk",
	"Metal Frame Desk",
	"Sleek Glass Desk",
	"Traditional Oak Desk",
	"Contemporary Desk",
	"Art Deco Desk",
	"Home Office Desk",
};
char admin_desks_descriptions[ADMIN_TEMPLATES_COUNT][DESK_DESCRIPTION_LEN] = {
	"A compact desk designed for small spaces, featuring a minimalist frame and ample writing surface.",
	"A sturdy, L-shaped desk with multiple storage compartments for organizing office essentials.",
	"An ergonomic standing desk with adjustable height settings for a healthier work experience.",
	"A classic wooden desk with a hutch, offering traditional charm and practical storage.",
	"A sleek glass-top desk with a modern design, perfect for contemporary workspaces.",
	"A versatile foldable desk, ideal for temporary setups or portable use.",
	"A spacious U-shaped desk, providing maximum surface area for multitasking.",
	"A student desk with built-in shelves and a compact footprint for dorm rooms.",
	"A wall-mounted desk that saves floor space while offering a functional work surface.",
	"A mid-century modern desk with clean lines and retro-inspired accents.",
	"A gaming desk equipped with cable management features and a durable build for intensive use.",
	"A vanity desk with a mirror and drawers, doubling as a makeup station.",
	"A contemporary open-frame desk with a minimalist design and industrial metal accents.",
	"A modular desk that can be configured in multiple ways to suit individual needs.",
	"A secretary desk with a fold-down writing surface and concealed storage.",
	"A drafting desk with an adjustable angled surface for sketching or technical work.",
	"A rustic farmhouse desk made of reclaimed wood with a weathered finish.",
	"A corner desk with rounded edges and a space-saving design for tight rooms.",
	"A double-sided desk allowing two users to work simultaneously, ideal for shared spaces.",
	"A durable metal-frame desk with a modern industrial aesthetic and built-in shelf.",
	"A glass and chrome desk featuring a contemporary design and easy-to-clean surface.",
	"A standing desk converter that transforms any table into a height-adjustable desk.",
	"A vintage roll-top desk with a curved cover and multiple small compartments.",
	"A floating shelf desk with integrated wall brackets for a clutter-free look.",
	"A laptop desk with a lightweight design and a dedicated space for cables.",
	"A multifunctional desk with integrated power outlets and USB ports.",
	"A children’s desk with vibrant colors and a storage drawer for art supplies.",
	"A reception desk with a polished finish and curved front panel for a professional setup.",
	"A crafting desk with adjustable shelves and ample surface area for DIY projects.",
	"A dual-monitor desk with an extended work surface for tech-heavy setups.",
	"A contemporary wooden desk with beveled edges and built-in file drawers.",
	"A collapsible desk designed for quick assembly and storage efficiency.",
	"A writing desk with a slim profile and a single pull-out drawer.",
	"A tiered desk with multiple levels for organizing devices and accessories.",
	"A Scandinavian-inspired desk with natural wood tones and minimalist design.",
	"A reversible L-shaped desk that adapts to left- or right-handed configurations.",
	"A partner desk with two identical workspaces connected by a central unit.",
	"A luxury executive desk made from premium materials and featuring detailed craftsmanship.",
	"A gaming desk with RGB lighting and a built-in cup holder for added convenience.",
	"A corner workstation with multiple shelves and cable management options.",
	"A vintage-inspired desk with brass hardware and intricate woodwork.",
	"An adjustable drafting table with a tiltable surface and side storage.",
	"A tech desk with a cable tray and grommet holes for seamless wire organization.",
	"A compact urban desk with a modern look and integrated side shelves.",
	"A writing desk with a tempered glass surface and a durable steel frame.",
	"A hybrid vanity/desk combo featuring a fold-up mirror and discreet storage.",
	"A minimalist folding desk that blends seamlessly into any decor.",
	"A space-saving ladder desk with shelves for books and decor above the work surface.",
	"A classic oak desk with a rich finish and dovetail-jointed drawers for durability.",
};

void err(char* error) {
	printf("Something really bad happened: %s\n", error);
	exit(1);
}
void init_crypto() {
	srand(time(NULL));

	// secp256r1 curve
	mpz_init_set_str(P256.p, "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);
    mpz_init_set_str(P256.a, "115792089210356248762697446949407573530086143415290314195533631308867097853948", 10);
    mpz_init_set_str(P256.b, "41058363725152142129326129780047268409114441015993725554835256314039467401291", 10);
    mpz_init_set_str(P256.n, "115792089210356248762697446949407573529996955224135760342422259061068512044369", 10);

    mpz_t Ox, Oy;
    mpz_init_set_ui(Ox, 0);
    mpz_init_set_ui(Oy, 0);

    point_init(&O, Ox, Oy, NULL, NULL);
    mpz_clear(Ox);
    mpz_clear(Oy);

	// initialize generator point for this curve
    mpz_t Gx, Gy;
    mpz_init_set_str(Gx, "48439561293906451759052585252797914202762949526041747995844080717082404635286", 10);
    mpz_init_set_str(Gy, "36134250956749795798585127919587881956611106672985015071877198253568414405109", 10);

    point_init(&G, Gx, Gy, &P256, &O);
    mpz_clear(Gx);
    mpz_clear(Gy);
}

void get_str(char* str, size_t len) {
	fgets(str, len, stdin);
	char* last_char = &str[strlen(str)-1];
	if (*last_char == '\n')
		*last_char = '\0';
}

int pick_opt(bool new_line) {
	char buf[8] = {}, *end = NULL;
	if (new_line)
		printf("> ");
	scanf("%7s%*c", buf);
	return strtol(buf, &end, 10); // maybe could serve as got overwrite to execve
}

// vulnerable function (only accessible to FDM GOLD users). doesn't check boundaries of out string and doesn't null terminate it
// this also allows a heap overflow
void format_colors(char* out_str, char* format_str, size_t format_len) {
	for (size_t i = 0; i < format_len; i++) {
		bool formatter = false;
		for (int j = 0; j < COLORS_COUNT && !formatter; j++) {
			size_t formatter_len = strlen(colors_keys[j]), formatted_len;
			if (!strncmp(&format_str[i], colors_keys[j], formatter_len)) {
				formatted_len = strlen(colors_values[j]);
				strncpy(out_str, colors_values[j], formatted_len);
				out_str += formatted_len;
				i += formatter_len - 1;
				formatter = true;
			}
		}
		if (!formatter)
			*out_str++ = format_str[i];
	}
}

void show_listing(desk_listingT* desk) {
	printf("Name: %s\n", desk->info->name);
	printf("Price: %.2f\n", desk->price); // nonce partial MSB leak is here (precision could be truncated resulting in a loss of some bits and wrong result)
	printf("Description: %s\n", desk->info->description);
	printf(ANSI_COLOR_RESET);
	puts("Desk details:");
	printf(" - Depth: %.2fcm\n", desk->size.depth);
	printf(" - Width: %.2fcm\n", desk->size.width);
	printf(" - Height: %.2fcm\n", desk->size.height);
}

void add_listing_beta() {

	desk_listingT* new_desk = (desk_listingT*)malloc(sizeof(desk_listingT));
	if (!new_desk)
		err("malloc failed");

	new_desk->info = (desk_listing_infoT*)malloc(sizeof(desk_listing_infoT));
	if (!new_desk->info)
		err("malloc failed");

	new_desk->info->poster_pubkey = &user_Q;
	new_desk->is_signed = false;
	char description[DESK_DESCRIPTION_LEN];


	bool done = false, inserted = false;

	while (!done) {
		puts(BETA_INSERTION_MENU);
		switch (pick_opt(1)) {
			case 1:
				puts("You will now be asked to describe the desk you are trying to sell! Be careful specifing ALL the fields correctly!");
				
				printf("Insert the listing name (displayed in the listings page): ");
				get_str(new_desk->info->name, sizeof(new_desk->info->name));

				puts(LISTING_SEPARATOR);
				puts("BETA Feature hint: you can create custom colored listing description messages in the following way:");
				puts("By inserting \"This is an $REDawesome $BLUEdesk$RESET!\", the description will show up in the for-sale list in this way:\n\n\"" "This is an " ANSI_COLOR_RED "awesome " ANSI_COLOR_BLUE "desk" ANSI_COLOR_RESET "!" "\"\n");
				puts("The available color formatters are:");
				for (int i = 0; i < COLORS_COUNT; i++)
					printf(" - %s\n", colors_keys[i]);
				puts(LISTING_SEPARATOR);
				printf("Insert the color-formatted listing description: ");
				get_str(description, sizeof(description));

				// vuln zone
				format_colors(new_desk->info->description, description, strnlen(description, sizeof(description)));
				// end vuln zone

				// vuln zone
				printf("Insert your target listing price: ");
				scanf("%f", &new_desk->price);
				// end vuln zone

				printf("Specify your desk's measures (Depth x Width x Height) in centimeters: ");
				if (scanf("%f x %f x %f", &new_desk->size.depth, &new_desk->size.width, &new_desk->size.height) == 3)
					inserted = true;
				break;
			case 2:
				if (inserted) {
					puts("Here's the preview of your Ad:");
					show_listing(new_desk);
				} else
					puts("Insert desk data first!");
				break;
			case 3:
				if (inserted) {
					new_desk->next = listings;
					listings = new_desk;
					listings_count++;
					puts("Listing added successfully");
					done = true;
				} else
					puts("Insert desk data first!");

				break;
			case 4:
				free(new_desk->info);
				free(new_desk);
				done = true;
				break;
			default:
				puts(INVALID_OPTION);
				break;
		}
	}


}

void add_listing() {

	/* getline(); */
	// use scanf %d without checking for filling the struct fields
	
	if (listings_count == MAX_LISTINGS) {
		puts("The max listings capacity has been reached, our databases are full at the moment!");
		return;
	}

	// check if user is admin
	if (point_eq(&user_Q, &admin_Q)) {
		printf("Do you want to try out our new BETA features? (y/n): ");
		char yes_no;
		scanf("%c%*c", &yes_no);
		if (tolower(yes_no) == 'y') {
			add_listing_beta();
			return;
		}
	}

	desk_listingT* new_desk = (desk_listingT*)malloc(sizeof(desk_listingT));
	if (!new_desk)
		err("malloc failed");

	new_desk->next = listings;

	puts("You will now be asked to describe the desk you are trying to sell! Be careful specifing ALL the fields correctly!");
	
	new_desk->info = (desk_listing_infoT*)malloc(sizeof(desk_listing_infoT));
	if (!new_desk->info)
		err("malloc failed");

	new_desk->info->poster_pubkey = &user_Q;

	printf("Insert the listing name (displayed in the listings page): ");
	get_str(new_desk->info->name, sizeof(new_desk->info->name));

	printf("Insert the listing description: ");
	get_str(new_desk->info->description, sizeof(new_desk->info->description));

	// vuln zone
	printf("Insert your target listing price: ");
	scanf("%f", &new_desk->price);
	// end vuln zone

	printf("Specify your desk's measures (Depth x Width x Height) in centimeters: ");
	if (scanf("%f x %f x %f", &new_desk->size.depth, &new_desk->size.width, &new_desk->size.height) == 3) {
		listings = new_desk;
		listings_count++;
	}
	else {
		free(new_desk->info);
		free(new_desk);
		return;
	}

	new_desk->is_signed = false;

	puts("Listing added successfully");
}

void sign_listing() {
	puts("Here are your unsigned listings:");
	int id = 1;
	for (desk_listingT* curr = listings; curr; curr = curr->next, id++) {
		if (curr->info->poster_pubkey != &user_Q // here all user inserted (even with other pub key) will pass
			|| curr->is_signed)
			continue;
		printf("- #%d (%s)\n", id, curr->info->name);
	}

	printf("Insert listing ID to sign: ");
	int target = pick_opt(false);
	desk_listingT* listing = listings;
	for (int id = 1; listing && target != id; listing = listing->next, id++) ;
	if (!listing) {
		puts("Specified listing not found!");
		return;
	}

	if (listing->info->poster_pubkey != &user_Q) {
		puts("That ad ins't yours!");
		return;
	}

	if (listing->is_signed) {
		puts("That listing is already signed!");
		return;
	}

	hashable_deskT hashable_desk_listing;

	// copy data from new desk to the hashable desk listing
	strncpy(hashable_desk_listing.name, listing->info->name, DESK_NAME_LEN);
	strncpy(hashable_desk_listing.description, listing->info->description, DESK_DESCRIPTION_LEN);
	hashable_desk_listing.size = listing->size;

	printf("Insert the signature for your desk: ");

	char r_s_inp[ECDSA_KEY_LEN];
	get_str(r_s_inp, sizeof(r_s_inp));
	size_t sig_len = strnlen(r_s_inp, sizeof(r_s_inp));
	size_t s_pos = 0;
	for (size_t i = 0; i < sig_len; i++) {
		if (!s_pos && !strncmp(&r_s_inp[i], ", ", strlen(", "))) {
			s_pos = i + strlen(", ");
			if (s_pos >= sig_len) {
				puts(SIGNATURE_FORMAT_INVALID);
				return;
			}
			r_s_inp[i++] = '\0';
			continue;
		}
		if (!isdigit(r_s_inp[i])) {
			puts(SIGNATURE_FORMAT_INVALID);
			return;
		}
	}
	if (s_pos == 0 || strlen(r_s_inp) == 0) {
		puts(SIGNATURE_FORMAT_INVALID);
		return;
	}

	mpz_init_set_str(listing->info->r, r_s_inp, 10);
	mpz_init_set_str(listing->info->s, &r_s_inp[s_pos], 10);

	if (!verify(listing->info->r, listing->info->s, (intptr_t)&hashable_desk_listing, sizeof(hashable_desk_listing), &user_Q, &G, &P256)) {
		puts(SIGNATURE_INVALID);
		return;
	}

	listing->is_signed = true;

	puts("Listing signed successfully");
}

void show_listings() {
	puts(LISTING_SEPARATOR);
	int id = 0;
	for (desk_listingT* curr = listings; curr; curr = curr->next) {
		printf("Listing #%d (%s):\n", ++id, curr->is_signed ? "signed" : "unsigned");
		show_listing(curr);
		puts(LISTING_SEPARATOR);
	}
}

void show_crypto_data() {
	printf("Insert listing id: ");
	int id = 0, target = pick_opt(false);
	if (target >= 1) {
		for (desk_listingT* curr = listings; curr; curr = curr->next) {
			if (++id == target) {
				if (!curr->is_signed) {
					puts("That listing isn't signed!");
					return;
				}
				printf("Sale authenticity data for listing #%d:\n", id);
				printf("Poster public key: ");
				mpz_out_str(stdout, 10, curr->info->poster_pubkey->x);
				printf(", ");
				mpz_out_str(stdout, 10, curr->info->poster_pubkey->y);
				puts("");
				printf("Signature: ");
				mpz_out_str(stdout, 10, curr->info->r);
				printf(", ");
				mpz_out_str(stdout, 10, curr->info->s);
				puts("");
				return;
			}
		}
	}
	puts("Invalid listing id");
}

void remove_listing() {

	// check if user is admin
	if (!point_eq(&user_Q, &admin_Q)) {
		puts("This feature is reserved for FDM GOLD subscribers!");
		return;
	}

	puts("Here are your listings:");
	int id = 1;
	for (desk_listingT* curr = listings; curr; curr = curr->next, id++) {
		if (curr->info->poster_pubkey != &user_Q) // here all user inserted (even with other pub key) will pass
			continue;
		printf("- #%d (%s)\n", id, curr->info->name);
	}

	printf("Insert listing ID to remove: ");
	int target = pick_opt(false);
	desk_listingT* listing = listings, *prev = NULL;
	for (int id = 1; listing && target != id; listing = listing->next, id++)
		prev = listing;
	if (!listing) {
		puts("Specified listing not found!");
		return;
	}

	if (listing->info->poster_pubkey != &user_Q) {
		puts("That ad ins't yours!");
		return;
	}

	if (prev)
		prev->next = listing->next;
	else
		listings = listing->next;
	listings_count--;

	free(listing->info);
	free(listing);

	puts("Listing removed!");

}

void market_menu() {
	bool logged_in = true;
	while (logged_in) {
		puts(MARKET_MENU);
		switch (pick_opt(1)) {
			case 1:
				add_listing();
				break;
			case 2:
				sign_listing();
				break;
			case 3:
				remove_listing();
				break;
			case 4:
				show_listings();
				break;
			case 5:
				show_crypto_data();
				break;
			case 6:
				puts("Sales for FDM GOLD subscriptions are currently closed");
				break;
			case 7:
				point_clear(&user_Q);
				printf("Logout completed!\n");
				logged_in = false;
				break;
			case 8:
				exit(0);
				break;
			default:
				puts(INVALID_OPTION);
				break;
		}
	}
}

void login_menu() {
	printf("Give me your ECDSA Public Key to be used: ");
	// ... some crypto shit ...
	char ecdsa_key_str[ECDSA_KEY_LEN];
	get_str(ecdsa_key_str, sizeof(ecdsa_key_str));
	size_t key_len = strnlen(ecdsa_key_str, sizeof(ecdsa_key_str));
	size_t y_pos = 0;
	for (size_t i = 0; i < key_len; i++) {
		if (!y_pos && !strncmp(&ecdsa_key_str[i], ", ", strlen(", "))) {
			y_pos = i + strlen(", ");
			if (y_pos >= key_len) {
				puts(KEY_FORMAT_INVALID);
				exit(-1);
			}
			ecdsa_key_str[i++] = '\0';
			continue;
		}
		if (!isdigit(ecdsa_key_str[i])) {
			puts(KEY_FORMAT_INVALID);
			exit(-1);
		}
	}
	if (y_pos == 0 || strlen(ecdsa_key_str) == 0) {
		puts(KEY_FORMAT_INVALID);
		exit(-1);
	}

	// check if point is in curve
	mpz_t Qx, Qy;
	mpz_init_set_str(Qx, ecdsa_key_str, 10);
	mpz_init_set_str(Qy, &ecdsa_key_str[y_pos], 10);

	point_init(&user_Q, Qx, Qy, &P256, &O);
	mpz_clear(Qx);
	mpz_clear(Qy);

	if (!check_point(&user_Q, &P256)) {
		puts(KEY_NOT_IN_CURVE);
		exit(-1);
	}

	// check if user is admin
	if (point_eq(&user_Q, &admin_Q)) {
		puts("You are trying to login as a GOLD FDM user!");
		puts("We have to double check it's really you before letting you in!");
		printf("Please sign this One Time Code to verify it's you: ");

		unsigned char random[AUTH_OTP_LEN];
		char hex_random[2*AUTH_OTP_LEN+1];
		read(urandom_fd, random, sizeof(random));
		bytes_to_hex(random, sizeof(random), hex_random);
		puts(hex_random);

		printf("Insert the signature: ");

		char r_s_inp[ECDSA_KEY_LEN];
		get_str(r_s_inp, sizeof(r_s_inp));
		size_t sig_len = strnlen(r_s_inp, sizeof(r_s_inp));
		size_t s_pos = 0;
		for (size_t i = 0; i < sig_len; i++) {
			if (!s_pos && !strncmp(&r_s_inp[i], ", ", strlen(", "))) {
				s_pos = i + strlen(", ");
				if (s_pos >= sig_len) {
					puts(SIGNATURE_FORMAT_INVALID);
					return;
				}
				r_s_inp[i++] = '\0';
				continue;
			}
			if (!isdigit(r_s_inp[i])) {
				puts(SIGNATURE_FORMAT_INVALID);
				return;
			}
		}
		if (s_pos == 0 || strlen(r_s_inp) == 0) {
			puts(SIGNATURE_FORMAT_INVALID);
			return;
		}

		mpz_t r, s;
		mpz_init_set_str(r, r_s_inp, 10);
		mpz_init_set_str(s, &r_s_inp[s_pos], 10);

		bool login_ok = verify(r, s, (intptr_t)random, sizeof(random), &admin_Q, &G, &P256);

		mpz_clear(r);
		mpz_clear(s);

		if (!login_ok) {
			puts(SIGNATURE_INVALID);
			return;
		}

		puts("Reminder: as a FDM GOLD subscriber, you have access to some extra features:");
		puts(" - Login authentication for improved security");
		puts(" - Customizable colors in listing descriptions (BETA)");
		puts(" - Listing preview (BETA)");
		puts(" - Remove listings");
	}

	printf("OK! Will be using (%s, %s) as your public key for your future listings!\n", ecdsa_key_str, &ecdsa_key_str[y_pos]);

	// here maybe print the user's profile (like if he does own a FDM GOLD subscription and some other things)

	market_menu();
}

void main_menu() {
	while (1) {
		puts(MAIN_MENU);
		switch (pick_opt(1)) {
			case 1:
				login_menu();
				break;
			case 2:
				close(urandom_fd);
				exit(0);
				break;
			default:
				puts(INVALID_OPTION);
				break;
		}
	}
}

void add_admin_listings() {
	urandom_fd = open("/dev/urandom", O_RDONLY);

	mpz_t d;
	mpz_init(d);

    // generate ECDSA private key
    unsigned char random[32];
    do {
        mpz_set_ui(d, 0);
        read(urandom_fd, random, sizeof(random));
        for (int i = 0; i < 32; i++) {
            for (int j = 7; j >= 0; j--) {
                mpz_mul_ui(d, d, 2);
                mpz_add_ui(d, d, (random[i] & (1 << j)) >> j);
            }
        }
    } while (mpz_cmp_ui(d, 0) == 0 || mpz_cmp(d, P256.n) >= 0);

#ifdef DEBUG
	printf("admin d: ");
	mpz_out_str(stdout, 10, d);
	puts(";");
#endif

    // calculate ECDSA public key
    admin_Q = scalar_multiplication(d, &G);

	hashable_deskT hashable_desk_listings[ADMIN_LISTINGS_COUNT];
	mpz_t r[ADMIN_LISTINGS_COUNT], s[ADMIN_LISTINGS_COUNT];

	for (int i = 0; i < ADMIN_LISTINGS_COUNT; i++) {
		mpz_init(r[i]);
		mpz_init(s[i]);

		desk_listingT* new_desk = (desk_listingT*)malloc(sizeof(desk_listingT));
		if (!new_desk)
			err("malloc failed");
		new_desk->next = listings;

		new_desk->info = (desk_listing_infoT*)malloc(sizeof(desk_listing_infoT));
		if (!new_desk->info)
			err("malloc failed");

		new_desk->info->poster_pubkey = &admin_Q;

		strncpy(new_desk->info->name, admin_desks_names[rand() % ADMIN_TEMPLATES_COUNT], DESK_NAME_LEN);

		strncpy(new_desk->info->description, admin_desks_descriptions[rand() % ADMIN_TEMPLATES_COUNT], DESK_DESCRIPTION_LEN);

		new_desk->size.depth = ((float)(rand() % 10000)) / 100.0f;
		new_desk->size.width = ((float)(rand() % 20000)) / 100.0f;
		new_desk->size.height = ((float)(rand() % 10000)) / 100.0f;
		new_desk->price = ((float)(rand() % 50000)) / 100.0f;

		// copy data from new desk to the hashable desk listing
		strncpy(hashable_desk_listings[i].name, new_desk->info->name, DESK_NAME_LEN);
		strncpy(hashable_desk_listings[i].description, new_desk->info->description, DESK_DESCRIPTION_LEN);
		hashable_desk_listings[i].size = new_desk->size;

		listings = new_desk;
		listings_count++;
	}

	// firmare ricorsivamente in modo da non freeare i k fino alla fine di tutte le signature e farlo invece tutti assieme
	// tutti gli mpz appena freeati che saranno esattamente num_mpz in sign (totale mpz freeati dall esecuzione della funzione sign) * numero di ricorsioni
	sign(r, s, (intptr_t)hashable_desk_listings, sizeof(hashable_desk_listings[0]), 0, sizeof(hashable_desk_listings)/sizeof(hashable_desk_listings[0]), d, &G, &P256, urandom_fd);

	desk_listingT* desk = listings;
	for (int i = 0; i < ADMIN_LISTINGS_COUNT; i++) {
		mpz_set(desk->info->r, r[i]);
		mpz_set(desk->info->s, s[i]);
		desk->is_signed = true;
		desk = desk->next;
	}
}

// G = 48439561293906451759052585252797914202762949526041747995844080717082404635286, 36134250956749795798585127919587881956611106672985015071877198253568414405109

int main() {
	puts(WELCOME_MENU);

	init_crypto();

	add_admin_listings();

	main_menu();

	return 0;
}
