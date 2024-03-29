# [DEPRECATED] Eesti idp integratsioonitestid
**Arenduseks on kasutatud Oracle Java jdk 1.8.0_162 versiooni.**
**HTTPS ühenduse jaoks on vajalik usaldada kasutatud sertifikaatide CA sertifikaat JAVA võtmehoidlas**

**NB! Antud testid on arenduses ning  muutuvad projekti edenedes.**

## Testide seadistamine ja käivitamine

Vajalik on Java VM eelnev installatsioon. Arenduseks on kasutatud Oracle Java jdk 1.8.0_162 versiooni.

1. Hangi Eesti idp lähtekood ning käivita antud teenus. Eesti iDP koodi ja käivitamise juhendid leiab [GitHubist](https://github.com/e-gov/IdP).
2. Hangi Eesti idp testid:

 `git clone https://github.com/e-gov/IdP-Test.git`

3. Seadista testid vastavaks testitava idp rakenduse otspunktidele. Selleks on kaks võimalust:

a) Võimalik on ette anda kahe erineva "profiili" properties faile "dev" ja "test" - vastavad properties failid [application-dev.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application-dev.properties) ja [application-test.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application-test.properties). Vaikeväärtusena on kasutusel profiil "dev", kuid seda on võimalik käivitamisel muuta parameetriga. Vaikeväärtused on seadistatud [application.properties](https://github.com/e-gov/IdP-Test/blob/master/src/test/resources/application.properties) failis.

b) Andes vastavad parameetrid ette testide käivitamisel (kirjeldus testide käivitamise punktis)

Parameetrite kirjeldus:

**idp** - Identity Provider, teenus kes pakub autentimist.

| Parameeter | Vaikeväärtus | Kirjeldus |
|------------|--------------|-----------|
| test.idp.idpUrl | http://localhost:8080 | Testitava idp teenuse Url ja port. |
| test.idp.idpMetadataUrl | /metadata | Teenuse metaandmete otspunkt. |
| test.idp.idpStartUrl | /metadata | Teenuse metaandmete otspunkt. |
| test.idp.idpMidWelcomeUrl | /midwelcome | Teenuse mobiilID autentimise otspunkt. |
| test.idp.idpMidAuthUrl | /midauth | Teenuse mobiilID autentimise alustamise otspunkt. |
| test.idp.idpMidCheckUrl | /midcheck | Teenuse mobiilID autentimise staatuse kontrolli otspunkt. |
| test.idp.eidasNodeMetadata | http://localhost:8080/metadata | Liidestatud eIDAS Nodei URL, port ja metaandmete otspunkt |
| test.idp.keystore | classpath:samlKeystore.jks | Võtmehoidla asukoht testides kasutatavate võtmete hoidmiseks. |
| test.idp.keystorePass | changeit | Võtmehoidla parool. |
| test.idp.requestSigningKeyId | test_sign | Võtmehoidlas oleva võtme alias mida kasutatakse SAML päringu allkirjastamiseks. eIDAS sõlme päringu simuleerimiseks. |
| test.idp.requestSigningKeyPass | changeit | Võtme parool. |
| test.idp.responseDecryptionKeyId | test_sign | Võtmehoidlas oleva võtme alias mida kasutatakse SAML päringu allkirjastamiseks. eIDAS sõlme päringu simuleerimiseks. |
| test.idp.responseDecryptionKeyPass | changeit | Võtme parool. |
| test.idp.xRoadMockUrl | http://localhost:9999 | X-tee mocki url (Wiremock) |
| test.idp.xRoadUrl | http://example.com | X-tee turvaserveri url |
| test.idp.idpBackEndUrl | http://localhost:8080 | Testitava idp teenuse Tomcat-i Url ja port. |
| test.idp.idpDomainName | localhost | Testitava idp teenuse domeeni nimi |


4. Käivita testid:

Testimiseks käivita kõik testid

`./mvnw clean test`

Testidele parameetrite ette andmine käivitamisel:

`./mvnw clean test -Dtest.idp.idpUrl=http://localhost:1881`

5. Kontrolli testide tulemusi

a) Testid väljastavad raporti ja logi jooksvalt käivituskonsoolis

b) Surefire pistikprogramm väljastab tulemuste raporti ../target/surefire-reports kausta. Võimalik on genereerida ka html kujul koondraport. Selleks käivitada peale testide käivitamist käsk:

`./mvnw surefire-report:report-only`

Html raport on leitav ../target/site/ kaustast.
