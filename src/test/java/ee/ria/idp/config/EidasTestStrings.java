package ee.ria.idp.config;

public class EidasTestStrings {
    //LOA levels
    public static final String LOA_LOW = "http://eidas.europa.eu/LoA/low";
    public static final String LOA_SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    public static final String LOA_HIGH = "http://eidas.europa.eu/LoA/high";

    //SAML attributes
    public static final String FN_DATE = "DateOfBirth";
    public static final String FN_PNO = "PersonIdentifier";
    public static final String FN_FAMILY = "FamilyName";
    public static final String FN_FIRST = "FirstName";
    public static final String FN_ADDR = "CurrentAddress";
    public static final String FN_GENDER = "Gender";
    public static final String FN_BIRTH_NAME = "BirthName";
    public static final String FN_BIRTH_PLACE = "PlaceOfBirth";
    public static final String FN_LEGAL_NAME = "LegalName";
    public static final String FN_LEGAL_PNO = "LegalPersonIdentifier";

    //Test data strings
    public static final String DEFATTR_FIRST = "MARY ÄNN";
    public static final String DEFATTR_FAMILY = "O’CONNEŽ-ŠUSLIK TESTNUMBER";
    public static final String DEFATTR_PNO = "60001019906";
    public static final String DEFATTR_DATE = "2000-01-01";
    public static final String DEFATTR_BIRTH_NAME = "Test-Birth-First-Last-Name";
    public static final String DEFATTR_BIRTH_PLACE = "Country";
    public static final String DEFATTR_ADDR = "Street 1, Flat 3, Village 2, Country7";
    public static final String DEFATTR_GENDER = "Male";
    public static final String DEFATTR_LEGAL_NAME = "Good Company a/s";
    public static final String DEFATTR_LEGAL_PNO = "292938483902";
}
