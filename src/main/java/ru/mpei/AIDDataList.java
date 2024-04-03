package ru.mpei;

import lombok.Data;

@Data
public class AIDDataList {
    private String name;
    private boolean isguid;
    private long timestamp;

    public AIDDataList(String name, boolean isguid, long timestamp) {
        this.name = name;
        this.isguid = isguid;
        this.timestamp = timestamp;
    }

}
