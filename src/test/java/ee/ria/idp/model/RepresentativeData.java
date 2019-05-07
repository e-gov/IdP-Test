package ee.ria.idp.model;


import java.util.Map;


public class RepresentativeData {
    //Snakeyaml needs seperate named map for deserialization https://stackoverflow.com/a/42565447
    public Map<String, Representative> map;

}

