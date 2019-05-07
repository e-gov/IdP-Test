package ee.ria.idp.model;

import lombok.Data;

import java.util.List;

public @Data
class Representative {
    private String code;
    private String forename;
    private String surname;
    private String dateOfBirth;
    private String certificate;
    private List<LegalPerson> companies;
}
