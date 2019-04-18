package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

/*import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;*/
/*import com.rashed.pharmacy.model.CustomerPurchaseMain;
import com.rashed.pharmacy.dao.CustomerPurchaseMainDAO;
import com.rashed.pharmacy.dao.CustomerPurchaseProductDAO;*/
import com.rashed.pharmacy.model.CustomerTransactionMain;
import com.rashed.pharmacy.dao.CustomerTransactionMainDAO;
import com.rashed.pharmacy.dao.CustomerTransactionProductDAO;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String LIST_CUSTOMERTRANSACTIONMAIN = "/jsp/order/customerTransactionMainList.jsp";
	private static String ENQUIRY = "/jsp/order/customerTransactionMainEnquiry.jsp";
	private static String LIST_CUSTOMERTRANSACTIONPRODUCT = "/jsp/order/customerTransactionProductList.jsp";
	private static String LIST_CUSTOMERTRANSACTIONPRODUCTENQUIRY = "/jsp/order/customerTransactionProductListEnquiry.jsp";
	
	private CustomerTransactionMainDAO ctmdao;
	private CustomerTransactionProductDAO ctpdao;
	
	String action = "";
	String message = "";
	
       
    public CustomerTransactionMainController() {
        super();
        ctmdao = new CustomerTransactionMainDAO();
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
			String transaction_id = request.getParameter("transaction_id");
			String strOrderStatus = ctmdao.getSelectedOtherID(transaction_id).getOrder_status();
			String date_time = ctmdao.getSelectedOtherID(transaction_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				ctmdao.delete(transaction_id);
				message = "Transaction " + transaction_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Transaction can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_CUSTOMERTRANSACTIONMAIN;
			request.setAttribute("customerTransactionMains", ctmdao.getAllCustomerTransactionMain());
		} else if(action.equalsIgnoreCase("customerTransactionMainList")){
			forward = LIST_CUSTOMERTRANSACTIONMAIN;
			request.setAttribute("customerTransactionMains", ctmdao.getAllCustomerTransactionMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_id = request.getParameter("transaction_id");
			CustomerTransactionMain ctm = ctmdao.getCustomerTransactionMainById(transaction_id);
			request.setAttribute("customerTransactionMain", ctm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_CUSTOMERTRANSACTIONPRODUCT;
			
			String transaction_id = request.getParameter("transaction_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("customerTransactionProducts", ctpdao.getAllCustomerTransactionProductByMainIdDateTime(transaction_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("transaction_id", transaction_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			//request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			request.setAttribute("sumTotalAmount", ctpdao.sumTotalAmount(transaction_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("customerTransactionProductListEnquiry")){
			forward = LIST_CUSTOMERTRANSACTIONPRODUCTENQUIRY;
			
			String transaction_id = request.getParameter("transaction_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("customerTransactionProducts", ctpdao.getAllCustomerTransactionProductByMainIdDateTime(transaction_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("transaction_id", transaction_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", ctpdao.sumTotalAmount(transaction_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
