# Revue de code — gobinsec

Date : 2026-05-26

## Introduction

Gobinsec est un outil concis et utile : il extrait les dépendances d'un binaire Go via `debug/buildinfo`, interroge la base NVD, puis met en relation versions de dépendances et versions vulnérables. Le périmètre fonctionnel est clair, les fichiers sont bien découpés (une responsabilité par fichier), l'abstraction `Cache` permet trois implémentations (fichier, memcached, memcachier) et l'abstraction `Version` permet trois formats (sémantique, pseudo, date). Le projet est testé en partie (versions, match de vulnérabilités) et la configuration combine YAML et drapeaux CLI.

Cela étant, plusieurs défauts notables affectent la **correction**, la **robustesse** et la **maintenabilité**. Le plus grave est silencieux : la clé d'API NVD configurée n'est jamais envoyée. Plusieurs choix de conception fragilisent l'exécution concurrente (un `os.Exit` dans une goroutine, un pool ad hoc qui contourne le rate-limit en réduisant le parallélisme à 1). Enfin, il existe quelques incohérences dans la gestion de la configuration et du cache qui peuvent surprendre l'utilisateur (overwrite des valeurs YAML par les drapeaux CLI, entrée polluante « test » dans le cache Memcachier, permissions 0644 sur le cache fichier). L'ensemble est corrigeable rapidement.

## Problèmes identifiés et pistes de correction

### 1. La clé d'API NVD n'est jamais envoyée *(critique — bug fonctionnel)*

Dans [dependency.go:106-118](../gobinsec/dependency.go#L106-L118), un objet `*http.Request` est construit avec l'en-tête `apiKey`, mais la requête réellement émise est `http.Get(url)`. L'objet `request` est inutilisé : la clé n'est jamais transmise au serveur. L'utilisateur croit bénéficier du quota élevé mais reste plafonné au quota anonyme, ce qui rend le drapeau `-wait` inefficace en pratique (puisque la branche `WaitWithKey` est suivie alors que NVD voit une requête anonyme).

**Piste** : remplacer `http.Get(url)` par `(&http.Client{Timeout: …}).Do(request)`.

### 2. `os.Exit(1)` dans une goroutine *(critique — robustesse)*

Dans [binary.go:81-94](../gobinsec/binary.go#L81-L94), `LoadVulnerabilities` appelle `os.Exit(1)` dès qu'une dépendance échoue. Conséquences :
- Le processus se termine sans exécuter `CacheInstance.Close()`, donc le cache fichier accumulé pendant la passe est **perdu**.
- Une seule erreur réseau transitoire (500, timeout) sur N dépendances rend tout le run inutilisable.
- Le code de sortie magique `1` court-circuite la sémantique des constantes `CodeVulnerable`/`CodeError` du `main.go`.

**Piste** : remonter l'erreur via un canal d'erreurs (ou la stocker dans la dépendance), attendre la fin du `WaitGroup`, puis traiter dans `main`. Au minimum, utiliser `CodeError` et appeler `CacheInstance.Close()` avant `os.Exit`.

### 3. Pool de goroutines fragile et stratégie « -wait » incorrecte *(important)*

[binary.go:58-94](../gobinsec/binary.go#L58-L94) construit un pool ad hoc :
- Toutes les dépendances sont poussées dans le canal **avant** que les workers ne démarrent ; les workers utilisent `select { case <-ch ; default: return }`. Un worker peut donc sortir au premier moment où le canal est temporairement vide, alors qu'un autre worker s'apprête à finir et à libérer du travail.
- Quand `config.Wait` est vrai, le nombre de workers est forcé à 1 — ce qui supprime la concurrence au lieu de la cadencer.

**Piste** : utiliser le patron canonique `for dep := range ch` (les workers ferment proprement quand le producteur appelle `close(ch)`), et imposer la cadence via `golang.org/x/time/rate.NewLimiter` au lieu de réduire le parallélisme à 1.

### 4. `config.Verbose` et `config.Cache` écrasent le YAML *(important)*

[config.go:46-47](../gobinsec/config.go#L46-L47) assigne inconditionnellement les flags CLI à `config.Verbose` / `config.Cache`. Si l'utilisateur définit `verbose: true` dans son YAML mais ne passe pas `-verbose`, la valeur passe silencieusement à `false`. Comportement incohérent avec `Strict` et `Wait` qui n'écrasent que si le flag est positionné.

**Piste** : aligner la logique sur celle de `Strict`/`Wait` (`if verbose { config.Verbose = true }`), ou utiliser des `*bool` pour distinguer « non précisé » de `false`.

### 5. Pas de timeout sur les appels HTTP NVD *(important)*

[dependency.go:115](../gobinsec/dependency.go#L115) utilise `http.Get` (client par défaut, **aucun timeout**). Si NVD répond lentement ou laisse pendre la connexion, le run se bloque indéfiniment.

**Piste** : déclarer un `http.Client{Timeout: 30 * time.Second}` au niveau package et l'utiliser pour toutes les requêtes.

### 6. `Open()` du cache Memcachier injecte une clé « test » polluante *(important)*

[cache-memcachier.go:119-126](../gobinsec/cache-memcachier.go#L119-L126) écrit une entrée `test=test` dans le cache à chaque démarrage. Elle reste visible à tous les clients du même serveur Memcachier (souvent multi-tenant) jusqu'à expiration.

**Piste** : utiliser un `Get` sur une clé inexistante et accepter `ErrCacheMiss` comme preuve de connectivité, ou implémenter un Ping spécifique.

### 7. Permissions trop ouvertes sur le fichier de cache *(important — sécurité)*

[cache-file.go:135](../gobinsec/cache-file.go#L135) écrit le cache avec le mode `0644`. Même si le contenu n'est pas hautement sensible, c'est un fichier sous `~/`, lisible par tout autre utilisateur du poste.

**Piste** : utiliser `0600`.

### 8. Le canal d'erreur dans la goroutine fait sortir avec le code `1` au lieu d'une constante nommée *(mineur)*

[binary.go:87](../gobinsec/binary.go#L87) : `os.Exit(1)` est codé en dur, ce qui contredit l'effort fait dans `main.go` (`CodeVulnerable=1`, `CodeError=2`). Aujourd'hui, un échec NVD est rapporté comme « vulnérable » à l'appelant CI.

**Piste** : utiliser `CodeError` (au minimum) — mais cf. problème n°2 qui rend cette correction définitive.

### 9. `NewDependency` déclare un `error` jamais retourné *(propreté)*

[dependency.go:44-51](../gobinsec/dependency.go#L44-L51) renvoie `(*Dependency, error)` mais ne produit jamais d'erreur. Le `err` est ensuite vérifié dans l'appelant pour rien. Cette signature ment sur le contrat.

**Piste** : retirer le retour `error` et simplifier le site d'appel.

### 10. Constantes mortes *(propreté)*

[binary.go:13-16](../gobinsec/binary.go#L13-L16) : `MinimumBinaryDependencyFields` et `MinimumBinaryLines` ne sont jamais référencées.

**Piste** : supprimer.

### 11. `UnknownVersion.Compare` renvoie systématiquement une erreur, ce qui force un match *(piège)*

[vulnerability.go:92-127](../gobinsec/vulnerability.go#L92-L127) interprète toute erreur de comparaison comme « match » (`return true`). Combiné à [version_unknown.go:16-18](../gobinsec/version_unknown.go#L16-L18), une dépendance à version « inconnue » est *toujours* signalée vulnérable dès qu'une CVE existe pour son nom. C'est probablement intentionnel (prudence), mais ce n'est ni documenté ni testé.

**Piste** : ajouter un test explicite et documenter le comportement, ou rendre ce comportement configurable (équivalent au mode `-strict`).

### 12. État global `config` *(maintenabilité / testabilité)*

[config.go:24](../gobinsec/config.go#L24) déclare `var config Config` en variable globale lue partout (`config.Strict`, `config.APIKey`, `config.Verbose`, etc.). Cela complique les tests parallèles et masque les dépendances réelles des fonctions.

**Piste** : passer la configuration en paramètre (au moins aux constructeurs `NewBinary`, `NewCache`, `WaitBeforeCall`), ou encapsuler dans un objet `Scanner`.

### 13. `Match.InList` utilise `reflect.DeepEqual` *(performance, propreté)*

[vulnerability.go:131-144](../gobinsec/vulnerability.go#L131-L144) recourt à `reflect.DeepEqual` sur des structures simples. C'est lent et peu sûr en cas d'ajout de champ non-comparable.

**Piste** : comparer les quatre champs `Version` directement (la comparaison structurelle suffit puisque l'interface a une méthode `Compare`).

### 14. Comparaison de dates en chaînes *(propreté)*

[cache-file.go:142-149](../gobinsec/cache-file.go#L142-L149) compare des timestamps formatés (`cache.Date < limit`). Cela ne fonctionne que par chance de l'ordonnancement lexicographique d'ISO-8601 ; un fuseau ou un format différent casse silencieusement la purge.

**Piste** : stocker la date en `time.Time` (yaml prend en charge) ou parser avant comparaison.

### 15. Deux clients memcache distincts *(dette technique)*

`go.mod` requiert à la fois `github.com/bradfitz/gomemcache` et `github.com/memcachier/gomemcache`. Le second est un fork qui ajoute `SetAuth`. Maintenir deux clients pour la même technologie multiplie la surface de bug.

**Piste** : passer entièrement sur le fork `memcachier` (qui supporte aussi l'usage non-authentifié) et supprimer l'autre dépendance.

### 16. Faute de frappe « Matchs » → « Matches » *(propreté)*

Présent dans la structure `Vulnerability.Matchs` et le code de rapport [binary.go:127](../gobinsec/binary.go#L127). Faute systématique mais publique (apparaît dans la sortie YAML utilisateur).

**Piste** : renommer en `Matches`. Note : changement de format de sortie (incompatible avec les scripts d'utilisateurs qui parseraient la sortie).

### 17. Pseudo-version : offsets magiques *(robustesse)*

[version_pseudo.go:28-29](../gobinsec/version_pseudo.go#L28-L29) : `start := len(text) - 27; end := start + 8`. Les nombres 27 et 8 sont opaques. Si le format de pseudo-version évolue (par exemple v2+), le parsing casse silencieusement (ou échoue et retombe sur `UnknownVersion`).

**Piste** : extraire les positions à partir de la structure connue (`split("-")`) ou documenter l'algorithme.

### 18. Pas de `context.Context` *(modernité Go)*

Toutes les fonctions IO (HTTP, memcached) ignorent `context.Context`. Pas de mécanisme d'annulation propre depuis `main`.

**Piste** : propager un contexte annulable au moins jusqu'aux appels HTTP.

### 19. Version de Go exigée trop récente *(packaging)*

`go.mod` exige `go 1.25.7`. Beaucoup d'environnements CI/distros n'ont pas encore cette version, alors que rien dans le code n'utilise de fonctionnalité spécifique > 1.21.

**Piste** : abaisser à `go 1.22` ou `go 1.23`, ce qui élargit la base installable.

### 20. Messages de test trompeurs *(qualité des tests)*

[vulnerability_test.go:31-36](../gobinsec/vulnerability_test.go#L31-L36) : les messages d'erreur disent « should not match » alors que l'assertion teste l'inverse. Lors d'une régression, le développeur perd du temps à diagnostiquer.

**Piste** : corriger les messages.

### 21. `println` au lieu de `fmt.Println` *(propreté)*

[main.go:31](../main.go#L31) et lignes voisines : `println` est le builtin qui écrit sur stderr sans garantie de format. Mélange avec `fmt.Printf` sur stdout/stderr partout ailleurs.

**Piste** : uniformiser sur `fmt.Fprintln(os.Stderr, …)` pour les erreurs.

## Correctifs

- **#1** — [gobinsec/dependency.go](../gobinsec/dependency.go) : remplacement de `http.Get(url)` par `client.Do(request)`, l'en-tête `apiKey` est désormais effectivement transmis à NVD.
- **#5** — [gobinsec/dependency.go](../gobinsec/dependency.go) : introduction de la constante `HTTPRequestTimeout = 30 * time.Second` et utilisation d'un `http.Client{Timeout: HTTPRequestTimeout}` pour les appels NVD.
