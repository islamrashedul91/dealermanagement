package com.rashed.pharmacy.controller;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.dao.SalesProductDAO;

/*import com.rashed.pharmacy.model.CustomerPurchaseProduct;
import com.rashed.pharmacy.dao.CustomerPurchaseProductDAO;*/
import com.rashed.pharmacy.model.CustomerTransactionProduct;
import com.rashed.pharmacy.dao.CustomerTransactionProductDAO;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String LIST_CUSTOMERTRANSACTIONPRODUCT = "/jsp/order/customerTransactionProductList.jsp";
	private static String ENQUIRY = "/jsp/order/customerTransactionProductEnquiry.jsp";
	
	private CustomerTransactionProductDAO ctpdao;
	
	String action = "";
	String message = "";
	
       
    public CustomerTransactionProductController() {
        super();
        ctpdao = new CustomerTransactionProductDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String transaction_product_id = request.getParameter("transaction_product_id");
			String strOrderStatus = ctpdao.getSelectedOtherID(transaction_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				ctpdao.delete(transaction_product_id);
				message = "Transaction " + transaction_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Transaction can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_CUSTOMERTRANSACTIONPRODUCT;
			request.setAttribute("customerTransactionProducts", ctpdao.getAllCustomerTransactionProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("customerTransactionProductList")){
			forward = LIST_CUSTOMERTRANSACTIONPRODUCT;
			request.setAttribute("customerTransactionProducts", ctpdao.getAllCustomerTransactionProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_product_id = request.getParameter("transaction_product_id");
			CustomerTransactionProduct ctp = ctpdao.getCustomerTransactionProductById(transaction_product_id);
			request.setAttribute("customerTransactionProduct", ctp);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String transaction_product_id = request.getParameter("transaction_product_id");
			CustomerTransactionProduct ctp = ctpdao.getCustomerTransactionProductById(transaction_product_id);
			request.setAttribute("customerTransactionProduct", ctp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
