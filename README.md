# Eesti idp integratsioonitestid


**NB! Antud testid on arenduses ning  muutuvad projekti edenedes.**

## Testide seadistamine ja käivitamine

Vajalik on Java VM eelnev installatsioon. Arenduseks on kasutatud Oracle Java jdk 1.8.0_162 versiooni.

1. Hangi Eesti idp lähtekood ning käivita antud teenus. Eesti iDP koodi ja käivitamise juhendid leiab [GitHubist](https://github.com/e-gov/IdP).
2. Hangi Eesti idp testid:

 `git clone https://github.com/e-gov/IdP-Test.git`

3. Seadista testid vastavaks testitava klient rakenduse otspunktidele. Selleks on kaks võimalust:

a) Võimalik on ette anda kahe erineva "profiili" properties faile "dev" ja "test" - vastavad properties failid [application-dev.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application-dev.properties) ja [application-test.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application-test.properties). Vaikeväärtusena on kasutusel profiil "dev", kuid seda on võimalik käivitamisel muuta parameetriga. Vaikeväärtused on seadistatud [application.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application.properties) failis.

b) Andes vastavad parameetrid ette testide käivitamisel (kirjeldus testide käivitamise punktis)

Parameetrite kirjeldus:

**idp** - Identity Provider, teenus kes pakub autentimist.

| Parameeter | Vaikeväärtus | Vajalik korduvkasutatavatele testidele | Kirjeldus |
|------------|--------------|----------------------------------------|-----------|
| test.idp.targetUrl | http://localhost:8889 | Jah | Testitava klientrakenduse Url ja port. |
| test.idp.MetadataUrl | /metadata | Jah | Teenuse metaandmete otspunkt. |
| test.idp.keystore | classpath:samlKeystore.jks | Ei | Võtmehoidla asukoht testides kasutatavate võtmete hoidmiseks. |
| test.idp.keystorePass | changeit | Ei | Võtmehoidla parool. |
| test.idp.responseSigningKeyId | test_sign | Ei | Võtmehoidlas oleva võtme alias mida kasutatakse SAML vastuse allkirjastamiseks. eIDAS sõlme vastuse simuleerimiseks. |
| test.idp.responseSigningKeyPass | changeit | Ei | Võtme parool. |

4. Käivita testid:

Testimiseks käivita kõik testid

`./mvnw clean test`

Testidele parameetrite ette andmine käivitamisel:

`./mvnw clean test -Dtest.idp.targetUrl=http://localhost:1881`

5. Kontrolli testide tulemusi

a) Testid väljastavad raporti ja logi jooksvalt käivituskonsoolis

b) Surefire pistikprogramm väljastab tulemuste raporti ../target/surefire-reports kausta. Võimalik on genereerida ka html kujul koondraport. Selleks käivitada peale testide käivitamist käsk:

`./mvnw surefire-report:report-only`

Html raport on leitav ../target/site/ kaustast.
