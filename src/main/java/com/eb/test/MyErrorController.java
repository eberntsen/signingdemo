package com.eb.test;

import org.springframework.boot.autoconfigure.web.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

@Controller
public class MyErrorController implements ErrorController {

    @GetMapping(value = "/error")
    public ResponseEntity handleError(HttpServletRequest request) {

        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (status != null) {
            Integer statusCode = Integer.valueOf(status.toString());

            if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Signing verification failed");
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);



    }

    @Override
    public String getErrorPath() {
        return null;
    }
}