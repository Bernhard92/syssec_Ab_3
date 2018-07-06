package ab3.impl.Jahrer_Isopp_Hribar;

import ab3.AB3;
import ab3.CertTools;
import ab3.PasswordTools;

public class AB3Impl implements AB3 {

    @Override
    public CertTools newCertToolsInstance() {
    	CertTool certTool = new CertTool(); 
    	return certTool;
    }

    @Override
    public PasswordTools newPasswordToolsInstance() {
		PasswordTool passwordTool = new PasswordTool(); 
		return passwordTool;
    }
    
    

}
