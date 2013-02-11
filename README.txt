[Sommaire]
1. Pré-requis
2. Compilation
3. Execution
4. Options
5. Notes

1. [Pré-requis]
Les outils nécessaires pour modifier / compiler le projet sont :
- Microsoft Visual Studio 2010 Express
- Windows Driver Kits pour Windows XP
- un compilateur C/C++ (ex: Devcpp)

2. [Compilation]
* Compilation de la partie "kernel_land"
	- ouvrir la console "x86 Free Build Environment" de "Windows Driver Kits" pour Windows XP
	- via la console se rendre dans le répertoire "kernel_land"
	- taper "build"
	- un fichier "myRootkit.sys" a été généré dans le répertoire "objfre_wxp_x86"
* Compilation de la partie "user_land"
	- ouvrir Devcpp et le fichier "communicate_with_rk.cpp" dans le répertoire "user_land"
	- compiler
	- un fichier "communicate_with_rk.exe" a été généré

3. [Execution]
- lancer "OSLOADER.exe" situé dans le répertoire "OsrLoader\kit\w2k\i386\Fre\"
- dans le champs "Driver path", charger le fichier "myRootkit.sys"
- cliquer sur "Register Service", puis "Start Service"
- le rootkit est chargé
- lancer dans une console "communicate_with_rk.exe" pour intéragir avec le rootkit
	
4. [Options]
-r							Cache le rootkit depuis la liste des drivers chargés par le système
							(Option nom implémentée pour le moment)
-p <process_name> || <pid> 	Cache un process en l'enlevant de la double liste chaînée d'objets EPROCESS.
							Cette option prend en paramètre le nom du processus ou son PID.
-e <process_name> || <pid> 	Remplace le token du processus choisi par le token du processus System.
							Cette option prend en paramètre le nom du processus ou son PID.
							
5. [Notes]
- Cacher ou élever les privilèges d'un processus en donnant son nom n'est pas fiable, car le rootkit parcourera
  la double liste chaînée d'objets EPROCESS jusqu'à en trouver un dont le champs ImageFileName correspond au nom
  de processus donné. Or si plusieurs processus ont le même nom, le rootkit risque de cacher le mauvais processus.
  Pour cela, il vaut mieux utiliser le PID d'un processus pour ces options (visible avec Process Explorer)
  
- L'option permettant de cacher un processus, enlève ce dernier de la liste d'objets EPROCESS. Le processus
  devient alors invisible pour des outils comme "Task Manager" ou "Process Explorer" car ces derniers ce basent
  sur cette liste pour retrouver les processus en activités.
  D'autre outils comme "IceSword" se basent sur la table "PspCidTable" pour retrouver les processus. Dans ce cas
  un processus masqué par le rootkit sera visible.

- Il est possible de causer un integer overflow lorsque l'on souhaite cacher ou élever les privilèges d'un processus
  en spécifiant son PID. Le rootkit fait appel à la fonction atoi() pour convertir le PID en entier, mais si l'on passe
  un PID trop grand, alors le système plantera. N'ayant pas réussi à utiliser "errno", pour contrôler le PID convertit
  en entier (if (errno == ERANGE) { /* integer too long */ } ), je n'ai pu corriger ce problème pour le moment.