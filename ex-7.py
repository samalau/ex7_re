# Samantha Newmark
# 346587629 
# Ex7

import csv

def load_global_pokemon_data(filename):
	try:
		expected_keys = {"ID", "Name", "Type", "HP", "Attack", "Can Evolve"}
		data_list = []
		with open(filename, mode='r', encoding='utf-8') as f:
			reader = csv.DictReader(f, delimiter=',')
			if not expected_keys.issubset(reader.fieldnames):
				raise Exception("CSV headers do not match expected keys")
			for row in reader:
				if not row or not row.get("ID", "").strip(): break
				try:
					data_list.append({
						"ID": int(row["ID"]),
						"Name": row["Name"].strip(),
						"Type": row["Type"].strip(),
						"HP": int(row["HP"]),
						"Attack": int(row["Attack"]),
						"Can Evolve": row["Can Evolve"].strip().upper()
					})
				except (ValueError, KeyError) as e: continue
		return data_list
	except Exception as e: print(f"ERROR: {e}")

global_pokemon_data = load_global_pokemon_data("hoenn_pokedex.csv")
owner_root = None

STARTER_POKE = {
	'1': 'Treecko',
	'2': 'Torchic',
	'3': 'Mudkip'
}

def new_pokedex():
	global owner_root
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)
	owner_name = prompt_user('owner_name').strip()
	try:
		if any(owner['owner'].lower().strip() == owner_name.lower().strip() for owner in sorted_owners):
			raise Exception
		print(PROMPT['starter_pokechoice'])
		display_menu(STARTER_POKE)
		check_choice = 'Invalid input.'
		while check_choice == 'Invalid input.':
			starter_choice = input(PROMPT['choice'] + " ").strip()
			check_choice = validate_choice(starter_choice, STARTER_POKE)
			if not check_choice: return resolve_menu('MAIN')
			if check_choice != 'Invalid input.':
				starter_pokechoice = check_choice
		starter_pokechoice = STARTER_POKE.get(starter_choice)
		if starter_pokechoice:
			starter_data = next((
				p for p in global_pokemon_data if p['Name'].lower().strip() == starter_pokechoice.lower().strip()
	 		), None)
			if starter_data:
				new_owner = create_owner_node(owner_name, starter_data)
				owner_root = insert_owner_bst(owner_root, new_owner)
				print(generate_output(
					"pokemon_created",
					owner_name=owner_name,
					starter_pokechoice=starter_pokechoice
				))
				return resolve_menu('MAIN')
	except Exception:
		print(generate_output("pokedex_already_exists", owner_name=owner_name))
		return resolve_menu('MAIN')


def insert_owner_bst(root, new_node):
	if root is None: return new_node
	if new_node['owner'].strip().lower() < root['owner'].strip().lower():
		root['left'] = insert_owner_bst(root['left'], new_node)
	elif new_node['owner'].strip().lower() > root['owner'].strip().lower():
		root['right'] = insert_owner_bst(root['right'], new_node)
	return root


def create_owner_node(owner_name, first_pokemon=None):
	return {
		'owner': owner_name.strip().lower(),
		'pokedex': [first_pokemon] if first_pokemon else [],
		'left': None,
		'right': None
	}


def delete_pokedex():
	global owner_root
	owner_name = prompt_user('owner_delete')
	if not find_owner_bst(owner_root, owner_name):
		print(generate_output("pokedex_not_found", owner_name=owner_name))
		return resolve_menu('MAIN')
	owner_root = delete_owner_bst(owner_root, owner_name)
	print(generate_output("pokedex_deleting", owner_name=owner_name))
	return resolve_menu('MAIN')


def release_pokemon_by_name(owner_node):
	if not owner_node: return resolve_menu('MAIN')
	pokemon_name = prompt_user('pokename_release')
	for pokemon in owner_node['pokedex']:
		if pokemon['Name'].lower().strip() == pokemon_name.lower().strip():
			print(generate_output(
				"pokemon_releasing",
				pokemon_name=pokemon['Name'],
				owner_name=owner_node['owner']
			))
			owner_node['pokedex'].remove(pokemon)
			return resolve_menu('PERSONAL', owner_node)
	print(generate_output(
		"pokemon_not_in_pokedex",
		pokemon_name=pokemon_name,
		owner_name=owner_node['owner']
	))
	return resolve_menu('PERSONAL', owner_node)


def evolve_pokemon_by_name(owner_node):
	if not owner_node: return
	pokemon_name = prompt_user('pokename_evolve')
	new_pokemon_data = None
	old_pokemon_name = None
	old_pokemon_id = None
	if any(p['Name'].lower().strip() == pokemon_name.lower().strip() for p in owner_node['pokedex']):
		pass
	else:
		print(generate_output(
			"pokemon_not_in_pokedex",
			pokemon_name=pokemon_name,
			owner_name=owner_node['owner']
		))
		return resolve_menu('PERSONAL', owner_node)
	for pokemon in owner_node['pokedex']:
		if pokemon['Name'].lower().strip() == pokemon_name.lower().strip() and pokemon['Can Evolve'] == 'TRUE':
			old_pokemon_name = pokemon['Name']
			old_pokemon_id = pokemon['ID']
			new_pokemon_data = next((p for p in global_pokemon_data if p['ID'] == old_pokemon_id + 1), None)
			if not new_pokemon_data:
				print(f"Pokemon {pokemon_name} cannot be evolved in {owner_node['owner']}'s Pokedex.")  # TODO WORDING
				return resolve_menu('PERSONAL', owner_node)
			new_pokemon_name = new_pokemon_data['Name']
			new_pokemon_id = new_pokemon_data['ID']
			print(generate_output(
				"pokemon_evolution",
				old_pokemon_name=old_pokemon_name,
				old_pokemon_id=old_pokemon_id,
				new_pokemon_name=new_pokemon_name,
				new_pokemon_id=new_pokemon_id
			))
			duplicate_pokemon = next((
				p for p in owner_node['pokedex']
				if p['ID'] == new_pokemon_id
			), None)
			if duplicate_pokemon:
				owner_node['pokedex'].remove(pokemon)
				print(generate_output(
					"pokemon_evolved_duplicate",
					new_pokemon_name=new_pokemon_name
				))
			else:
				owner_node['pokedex'].remove(pokemon)
				owner_node['pokedex'].append(new_pokemon_data)
			return resolve_menu('PERSONAL', owner_node)
	print(f"Pokemon {pokemon_name} cannot be evolved in {owner_node['owner']}'s Pokedex.")  # TODO WORDING
	return resolve_menu('PERSONAL', owner_node)


def add_pokemon_to_owner(owner_node):
	try:
		pokemon_id = prompt_user('pokename_add_id')

		try: pokemon_id = int(pokemon_id)
		except Exception: raise Exception

		pokemon_data = next((
			p for p in global_pokemon_data if p['ID'] == pokemon_id
		), None)
		if not pokemon_data: raise Exception
		if any(p['ID'] == pokemon_id for p in owner_node['pokedex']):
			print(generate_output("pokemon_already_exists"))
			return resolve_menu('PERSONAL', owner_node=owner_node)
		owner_node['pokedex'].append(pokemon_data)
		print(generate_output(
			"pokemon_added",
			pokemon_name=pokemon_data['Name'],
			pokemon_id=pokemon_id,
			owner_name=owner_node['owner']
		))
		return resolve_menu('PERSONAL', owner_node=owner_node)
	except Exception:
		print(generate_output("pokemon_invalid", pokemon_id=pokemon_id))
		if not owner_node: return resolve_menu('MAIN')
		return resolve_menu('PERSONAL', owner_node=owner_node)


def delete_owner_bst(root, owner_name):
	if root is None: return root
	target = owner_name.strip().lower()
	current = root['owner'].strip().lower()
	if target < current:
		root['left'] = delete_owner_bst(root['left'], owner_name)
	elif target > current:
		root['right'] = delete_owner_bst(root['right'], owner_name)
	else:
		if root['left'] is None: return root['right']
		elif root['right'] is None: return root['left']
		temp = find_min_node(root['right'])
		root['owner'] = temp['owner']
		root['pokedex'] = temp['pokedex']
		root['right'] = delete_owner_bst(root['right'], temp['owner'])
	return root


def print_owner_and_pokedex(node):
	print(f"\n{generate_output('owner_info', owner_name=node['owner'])}")
	for pokemon in node['pokedex']:
		print(generate_output("pokemon_info", **pokemon), "")


def bfs_traversal(root):
	if not root: return
	queue = [root]
	while queue:
		current = queue.pop(0)
		print_owner_and_pokedex(current)
		if current['left']: queue.append(current['left'])
		if current['right']: queue.append(current['right'])


def pre_order_traversal(root):
	if not root: return
	print_owner_and_pokedex(root)
	pre_order_traversal(root['left'])
	pre_order_traversal(root['right'])


def in_order_traversal(root):
	if not root: return
	in_order_traversal(root['left'])
	print_owner_and_pokedex(root)
	in_order_traversal(root['right'])


def post_order_traversal(root):
	if not root: return
	post_order_traversal(root['left'])
	post_order_traversal(root['right'])
	print_owner_and_pokedex(root)


def filter_pokemon_by_type(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			pokemon_type = prompt_user('certain_poketype').lower()
			if any(p['Type'].lower().strip() == pokemon_type.lower().strip() for p in owner_node['pokedex']):
				for pokemon in owner_node['pokedex']:
					if pokemon['Type'].lower().strip() == pokemon_type:
						print(generate_output("pokemon_info", **pokemon))
			else: raise Exception
		else: raise Exception
	except Exception: print(generate_output("pokemon_no_criteria_match"))
	finally: return resolve_menu('FILTER', owner_node)


def filter_pokemon_evolvable(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			if any(p['Can Evolve'] == 'TRUE' for p in owner_node['pokedex']):
				for pokemon in owner_node['pokedex']:
					if pokemon['Can Evolve'] == 'TRUE':
						print(generate_output("pokemon_info", **pokemon))
			else: raise Exception
		else: raise Exception
	except Exception: print(generate_output("pokemon_no_criteria_match"))
	finally: return resolve_menu('FILTER', owner_node)


def filter_pokemon_by_attack(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			try:
				user_input = float(prompt_user('attack_threshold').strip())
				try:
					if user_input != int(user_input): raise ValueError
				except Exception: raise ValueError
				min_attack = int(user_input) + 1
				if min_attack:
					if any(p['Attack'] >= min_attack for p in owner_node['pokedex']):
						for pokemon in owner_node['pokedex']:
							if pokemon['Attack'] >= min_attack:
								print(generate_output("pokemon_info", **pokemon))
					else: raise Exception
				else: raise ValueError
			except ValueError: raise Exception
		else: raise Exception
	except Exception: print(generate_output("pokemon_no_criteria_match"))
	finally: return resolve_menu('FILTER', owner_node)


def filter_pokemon_by_hp(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			try:
				user_input = float(prompt_user('hp_threshold').strip())
				try:
					if user_input != int(user_input): raise ValueError
				except Exception: raise ValueError
				min_hp = int(user_input) + 1
				if min_hp:
					if any(p['HP'] >= min_hp for p in owner_node['pokedex']):
						for pokemon in owner_node['pokedex']:
							if pokemon['HP'] >= min_hp:
								print(generate_output("pokemon_info", **pokemon))
					else: raise Exception
				else: raise ValueError
			except (ValueError, TypeError): raise Exception
		else: raise Exception
	except Exception: print(generate_output("pokemon_no_criteria_match"))
	finally: return resolve_menu('FILTER', owner_node)


def filter_pokemon_by_name(owner_node):
	try:
		start_letter = prompt_user('pokename_starting_letters').lower()
		if any(p['Name'].lower().strip().startswith(start_letter) for p in owner_node['pokedex']):
			for pokemon in owner_node['pokedex']:
				if pokemon['Name'].lower().strip().startswith(start_letter):
					print(generate_output("pokemon_info", **pokemon))
		else: raise Exception
	except Exception: print(generate_output("pokemon_no_criteria_match"))
	finally: return resolve_menu('FILTER', owner_node)


def find_owner_bst(root, owner_name):
	if root is None:
		return None
	if owner_name.lower().strip() == root['owner'].lower().strip():
		return root
	elif owner_name.lower().strip() < root['owner'].lower().strip():
		return find_owner_bst(root.get('left'), owner_name)
	elif owner_name.lower().strip() > root['owner'].lower().strip():
		return find_owner_bst(root.get('right'), owner_name)


def find_min_node(node):
	current = node
	while current and current['left'] is not None:
		current = current['left']
	return current


def gather_all_owners(root, arr):
	if root:
		gather_all_owners(root['left'], arr)
		arr.append(root)
		gather_all_owners(root['right'], arr)


def display_owners_sorted():
	if not owner_root:
		print("No owners at all.")
		return resolve_menu('MAIN')
	
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)
	if not sorted_owners:
		print("No owners at all.")
		return resolve_menu('MAIN')
	sorted_owners.sort(key=lambda x: len(x['pokedex']))

	print(generate_output(
		"section_title",
		title='The Owners we have, sorted by number of Pokemons'
	).strip())

	for owner in sorted_owners:
		print(generate_output(
			"owner_by_pokemon",
			owner_name=owner['owner'],
			pokemon_count=len(owner['pokedex'])
		))
	
	return resolve_menu('MAIN')


def print_all_owners():
	if not owner_root:
		print("No owners at all.")
		return resolve_menu('MAIN')
	
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)

	if sorted_owners:
		resolve_menu('TRAVERSAL')
		print("\n")
		return resolve_menu('MAIN')
	else:
		print("No owners at all.")
		return resolve_menu('MAIN')


def display_all_pokemon(owner_node):
	if not owner_node: return resolve_menu('MAIN')
	
	if any(p for p in owner_node['pokedex']):
		for pokemon in owner_node['pokedex']:
			print(generate_output("pokemon_info", **pokemon))
	else: print(generate_output("pokemon_no_criteria_match"))
	
	return resolve_menu('FILTER', owner_node)


def existing_pokedex():
	global owner_node

	owner_name = prompt_user('owner_name')
	
	if not owner_root:
		print("No owners at all.")
		return resolve_menu('MAIN')
	
	owner_node = find_owner_bst(owner_root, owner_name)
	if owner_node:
		print("\n")
		return resolve_menu('PERSONAL', owner_node)
	else:
		print(generate_output("pokedex_not_found", owner_name=owner_name))
		return resolve_menu('MAIN')


def execute_action(menu_map, owner_node=None):
	display_menu(menu_map)

	check_choice = 'Invalid input.'
	while check_choice == 'Invalid input.':
		choice = input(PROMPT['choice'] + " ").strip()
		check_choice = validate_choice(choice, menu_map)
		if not check_choice:
			if menu_map in [MAIN, TRAVERSAL] or not owner_node: return resolve_menu('MAIN')
			elif menu_map == PERSONAL: return resolve_menu('PERSONAL', owner_node=owner_node)
			elif menu_map == FILTER: return resolve_menu('FILTER', owner_node)
			else: return resolve_menu('MAIN')
		if check_choice != 'Invalid input.':
			choice = check_choice
	
	action_label, action = menu_map[choice]

	if menu_map in [PERSONAL, FILTER]:
		print_adjust = menu_map[choice][0]
		if print_adjust in ['Display Pokedex', 'Back', 'Back to Main']:
			if print_adjust == 'Display Pokedex':
				print('\n')
			else:
				print(f"{'Back to Pokedex Menu.' if print_adjust == 'Back' else 'Back to Main Menu.'}")
	
	if callable(action):
		try:
			code = getattr(action, "__code__", None)
			if code:
				num_positional_args = code.co_argcount
				num_defaults = len(getattr(action, "__defaults__", []) or [])
				required_args = num_positional_args - num_defaults
				if owner_node and required_args > 0:
					action(owner_node)
				else: action()
			else:
				try: action(owner_node)
				except TypeError: action()
		except TypeError:
			if owner_node:
				try: action(owner_node)
				except TypeError: action()
			else: action()
	
	if menu_map == TRAVERSAL:
		return resolve_menu('MAIN')


def generate_output(template_key, **kwargs):
	return templates[template_key].format(**kwargs)


def prompt_user(prompt_key):
	response = input(PROMPT[prompt_key] + " ")
	return response


def display_menu(menu_map):
	if menu_map == STARTER_POKE: options = "\n".join([f"{k}) {v}" for k, v in menu_map.items()])
	elif menu_map == TRAVERSAL: options = "\n".join([f"{k}) {v[0]}" for k, v in menu_map.items()])
	else: options = "\n".join([f"{k}. {v[0]}" for k, v in menu_map.items()])
	print(options)


def validate_choice(choice, menu_map):
	if choice in menu_map:
		return choice
	else:
		try:
			int(choice)
			print("Invalid choice.")
			return None
		except ValueError:
			print("Invalid input.")
			return 'Invalid input.'


def resolve_menu(menu, owner_node=None):
	if MENU[menu]['menu'] == MAIN:
		owner_node = None
		print(generate_output("section_title", title=MENU['MAIN']['title']).strip())
	
	elif MENU[menu]['menu'] == PERSONAL:
		title = MENU['PERSONAL']['title']
		if "{owner_name}" in title and owner_node:
			title=title.format(owner_name=owner_node['owner'])
		print(generate_output("subsection_title", title=title).strip())
	
	elif MENU[menu]['menu'] == FILTER:
		print(generate_output("subsection_title", title=MENU['FILTER']['title']).strip())
	
	elif MENU[menu]['menu'] == TRAVERSAL:
		pass

	execute_action(MENU[menu]['menu'], owner_node)


MAIN = {
	'1': ('New Pokedex', lambda: new_pokedex()),
	'2': ('Existing Pokedex', lambda: existing_pokedex()),
	'3': ('Delete a Pokedex', lambda: delete_pokedex()),
	'4': ('Display owners by number of Pokemon', lambda: display_owners_sorted()),
	'5': ('Print All', lambda: print_all_owners()),
	'6': ('Exit', lambda: exit_program())
}

PERSONAL = {
	'1': ('Add Pokemon', lambda owner_node: add_pokemon_to_owner(owner_node)),
	'2': ('Display Pokedex', lambda owner_node: resolve_menu('FILTER', owner_node)),
	'3': ('Release Pokemon', lambda owner_node: release_pokemon_by_name(owner_node)),
	'4': ('Evolve Pokemon', lambda owner_node: evolve_pokemon_by_name(owner_node)),
	'5': ('Back to Main', lambda: resolve_menu('MAIN'))
}

FILTER = {
	'1': ('Only a certain Type', lambda owner_node: filter_pokemon_by_type(owner_node)),
	'2': ('Only Evolvable', lambda owner_node: filter_pokemon_evolvable(owner_node)),
	'3': ('Only Attack above __', lambda owner_node: filter_pokemon_by_attack(owner_node)),
	'4': ('Only HP above __', lambda owner_node: filter_pokemon_by_hp(owner_node)),
	'5': ('Only names starting with letter(s)', lambda owner_node: filter_pokemon_by_name(owner_node)),
	'6': ('All of them!', lambda owner_node: display_all_pokemon(owner_node)),
	'7': ('Back', lambda owner_node: resolve_menu('PERSONAL', owner_node))
}

TRAVERSAL = {
	'1': ('BFS', lambda: bfs_traversal(owner_root)),
	'2': ('Pre-Order', lambda: pre_order_traversal(owner_root)),
	'3': ('In-Order', lambda: in_order_traversal(owner_root)),
	'4': ('Post-Order', lambda: post_order_traversal(owner_root))
}

MENU = {
    'MAIN': {'menu': MAIN, 'title': 'Main Menu'},
    'PERSONAL': {'menu': PERSONAL, 'title': "{owner_name}'s Pokedex Menu"},
    'FILTER': {'menu': FILTER, 'title': 'Display Filter Menu'},
    'TRAVERSAL': {'menu': TRAVERSAL}
}

PROMPT = {
	'choice': 'Your choice:',
	'owner_name': 'Owner name:',
	'owner_delete': 'Enter owner to delete:',
	'starter_pokechoice': 'Choose your starter Pokemon:',
	'pokename_add_id': 'Enter Pokemon ID to add:',
	'pokename_release': 'Enter Pokemon Name to release:',
	'pokename_evolve': 'Enter Pokemon Name to evolve:',
	'pokename_starting_letters': "Starting letter(s):",
	'certain_poketype': "Which Type? (e.g. GRASS, WATER): ",
	'attack_threshold': "Enter Attack threshold:",
	'hp_threshold': "Enter HP threshold:",
}

templates = {
	"": "",
	"section_title": "=== {title} ===",
	"subsection_title": "-- {title} --",
	"pokemon_info": "ID: {ID}, Name: {Name}, Type: {Type}, HP: {HP}, Attack: {Attack}, Can Evolve: {Can Evolve}",
	"pokemon_evolution": "Pokemon evolved from {old_pokemon_name} (ID {old_pokemon_id}) to {new_pokemon_name} (ID {new_pokemon_id}).",
	"pokemon_evolved_duplicate": "{new_pokemon_name} was already present; releasing it immediately.",
	"owner_info": "Owner: {owner_name}",
	"owner_by_pokemon": "Owner: {owner_name} (has {pokemon_count} Pokemon)",
	"pokemon_created": "New Pokedex created for {owner_name} with starter {starter_pokechoice}.",
	"pokedex_already_exists": "Owner '{owner_name}' already exists. No new Pokedex created.",
	"pokedex_not_found": "Owner '{owner_name}' not found.",
	"pokedex_deleting": "Deleting {owner_name}'s entire Pokedex...\nPokedex deleted.",
	"pokemon_no_criteria_match": "There are no Pokemons in this Pokedex that match the criteria.",
	"pokemon_added": "Pokemon {pokemon_name} (ID {pokemon_id}) added to {owner_name}'s Pokedex.",
	"pokemon_already_exists": "Pokemon already in the list. No changes made.",
	"pokemon_invalid": "ID {pokemon_id} not found in Honen data.",
	"pokemon_not_in_pokedex": "No Pokemon named '{pokemon_name}' in {owner_name}'s Pokedex.",
	"pokemon_releasing": "Releasing {pokemon_name} from {owner_name}.",
	"goodbye_message": "Goodbye!",
	"keyboard_interrupt": "\nGoodbye!"
}

def exit_program():
	print(generate_output("goodbye_message"))
	exit()

def main():
	try:
		while True:
			global owner_node
			owner_node = None
			resolve_menu('MAIN')
	except KeyboardInterrupt:
		print(generate_output("keyboard_interrupt"))
		exit()

if __name__ == "__main__":
	main()