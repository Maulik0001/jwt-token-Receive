package com.example.demo;

import java.security.Key;
import java.util.Base64;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONObject;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import com.google.gson.Gson;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;


@RestController
@EnableWebSecurity
@RequestMapping(value="/rest")
public class ReceiveController {

	@CrossOrigin
	@RequestMapping(value = "/jwtSecurityReceive", method = RequestMethod.POST , produces="application/json")
	public String jwtSecurityReceive(@RequestBody String jsonObjString, 
			HttpServletRequest request , HttpServletResponse response) {
		
		try {
			System.out.println("JWT Receive Called ::: "+jsonObjString);
			
			if(jsonObjString!=null) {
				String json = new String(JsonStringEncoder.getInstance().encodeAsUTF8(jsonObjString), "UTF-8");
				
				JSONObject jsonObj = new JSONObject(json);
				
				if(!jsonObj.isNull("jwtToken")) {
					
					String jwtToken = jsonObj.getString("jwtToken");

					parseJWT(jwtToken);
					
					System.out.println("jwtToken for receive side::"+jwtToken);
					
					
					HashMap<String, String> resultmap= new HashMap<String, String>();
					resultmap.put("message", "true");
					resultmap.put("jwtToken", "success");
					
					Gson gson=new Gson();
				
					return gson.toJson(resultmap);
				}
				
			}

		} catch (Exception e) {
			// TODO: handle exception
		}
		return null;
		
	}
	
	private static void parseJWT(String jwt) {
		System.out.println("jwt:::"+jwt);
		// SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		 
		/* final Key secret = MacProvider.generateKey(SignatureAlgorithm.HS256);
		 final byte[] secretBytes = secret.getEncoded();
		 final String base64SecretBytes = Base64.getEncoder().encodeToString(secretBytes);*/
		 
	    //This line will throw an exception if it is not a signed JWS (as expected)
	//	Claims claims = Jwts.parser().setSigningKey(base64SecretBytes).parseClaimsJws(jwt).getBody();
		
		final String secret = "JwtQwx@PeS!ense#22011992$MbPtl21";
		
	    Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(secret)).parseClaimsJws(jwt).getBody();
	    System.out.println("claims:::"+claims);
	    System.out.println("ID: " + claims.getId());
	    System.out.println("Subject: " + claims.getSubject());
	    System.out.println("Issuer: " + claims.getIssuer());
	    System.out.println("Expiration: " + claims.getExpiration());
	    
	}

}
