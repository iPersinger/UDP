package ru.mpei;

import lombok.Data;
@Data
public class AIDdata {
    private String name;

    private boolean isGUID;


    public AIDdata(String name, boolean isGUID) {
        this.name = name;
        this.isGUID = isGUID;
    }
}
