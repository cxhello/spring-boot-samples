package top.cxhello.webservice.entity;

import lombok.Data;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Data
public class UserDto {

    private Long id;

    private String userName;

    private Boolean active;

}
