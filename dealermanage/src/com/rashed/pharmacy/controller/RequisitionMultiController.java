package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.util.*;

public class RequisitionMultiController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/requisitionMultiAdd.jsp";
	private static String LIST_REQUISITIONMULTI = "/jsp/order/requisitionMultiList.jsp";
	private static String LIST_REQUISITIONPRODUCT = "/jsp/order/requisitionProductList.jsp";
	private static String REQUISITIONPRODUCT = "/jsp/order/requisitionProduct.jsp";
	private static String ENQUIRY = "/jsp/order/requisitionMultiEnquiry.jsp";
	private static String LIST_REQUISITIONPRODUCTENQUIRY = "/jsp/order/requisitionProductListEnquiry.jsp";
	
	private RequisitionMultiDAO rmdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	//private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	private RequisitionProductDAO rpdao;
	private SalesMainDAO smmdao;
	private AccountDAO adao;
	
	String action = "";
	String message = "";
	
       
    public RequisitionMultiController() {
        super();
        rmdao = new RequisitionMultiDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        smdao = new SalesmanInfoDAO();
        rpdao = new RequisitionProductDAO();
        smmdao = new SalesMainDAO();
        adao = new AccountDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String requisition_id = request.getParameter("requisition_id");
			//rmdao.delete(requisition_id);
			String strOrderStatus = rmdao.getSelectedOtherID(requisition_id).getOrder_status();
			String date_time = rmdao.getSelectedOtherID(requisition_id).getDate_time();
			//List list = rpdao.getAllRequisitionProductByMultiId(requisition_id, date_time);
			//if (!strOrderStatus.equals("A") && list.equals("") && list==null && list.size()==0) {
			if (!strOrderStatus.equals("A")) {
				rmdao.delete(requisition_id);
				message = "Order " + requisition_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				/*if (!strOrderStatus.equals("A") && !list.equals("") && list!=null){
					message = "Please delete product first !!!";
					request.setAttribute("success", message);
				} else {*/
					message = "Approved Order can not be deleted !!!";
					request.setAttribute("success", message);
				//}
			}
			forward=LIST_REQUISITIONMULTI;
			request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String requisition_id = request.getParameter("requisition_id");
			String strOrderStatus = rmdao.getSelectedOtherID(requisition_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				rmdao.cancel(requisition_id);
				message = "Order " + requisition_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Order can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_REQUISITIONMULTI;
			request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());
		} else if(action.equalsIgnoreCase("approve")){
			String requisition_id = request.getParameter("requisition_id");
			String date_time = rmdao.getSelectedOtherID(requisition_id).getDate_time();
			String strOrderStatus = rmdao.getSelectedOtherID(requisition_id).getOrder_status();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				rmdao.approve(requisition_id);
				// set requisition_product order_status='A' based on requisition_multi id [S]
				rpdao.approveByMultiRequisition(requisition_id, date_time);
				// set requisition_product order_status='A' based on requisition_multi id [E]
				
				// requisition_multi to sales_main [S]
				smmdao.requisitionMultiToSalesMain(requisition_id, date_time);
				// requisition_multi to sales_main [E]

				// for insert into sales_product one by one from a list based on requisition_product id and date time [S]
				rpdao.getRequisitionProductToSalesProduct(requisition_id, date_time);
				//spdao.requisitionProductToSalesProduct(requisition_id, date_time);
				// for insert into sales_product one by one from a list based on requisition_product id and date time [E]
				/*sdao.requisitionToSales(requisition_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				// for update stock one by one from a list based on requisition_multi id and date_time [S]
				rpdao.getProdcutIdForStockUpdate(requisition_id, date_time);
				// for update stock one by one from a list based on requisition_multi id and date_time [E]
				
				message = "Order " + requisition_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Order can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_REQUISITIONMULTI;
			request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String requisition_id = request.getParameter("requisition_id");
			RequisitionMulti rm = rmdao.getRequisitionMultiById(requisition_id);
			request.setAttribute("requisitionMulti", rm);
			// for get all the Product_id when update requisition [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when update requisition [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedCustomerId", rmdao.getSelectedOtherID(requisition_id).getCustomer_id());
			/*request.setAttribute("selectedProductId", rmdao.getSelectedOtherID(requisition_id).getProduct_id());
			request.setAttribute("selectedBonusId", rmdao.getSelectedOtherID(requisition_id).getBonus_id());*/
			request.setAttribute("selectedSalesmanId", rmdao.getSelectedOtherID(requisition_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("requisitionMultiList")){
			forward = LIST_REQUISITIONMULTI;
			request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String requisition_id = request.getParameter("requisition_id");
			RequisitionMulti rm = rmdao.getRequisitionMultiById(requisition_id);
			request.setAttribute("requisitionMulti", rm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_REQUISITIONPRODUCT;
			
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProductByMultiId(requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("requisition_multi_id", requisition_id);
			request.setAttribute("strDateTimeMulti", date_time);
			request.setAttribute("customerNameMulti", request.getParameter("customer_name"));
			request.setAttribute("customerMobileMulti", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", rpdao.sumTotalAmount(requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("requisitionProductListEnquiry")){
			forward = LIST_REQUISITIONPRODUCTENQUIRY;
			
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProductByMultiId(requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("requisition_multi_id", requisition_id);
			request.setAttribute("strDateTimeMulti", date_time);
			request.setAttribute("customerNameMulti", request.getParameter("customer_name"));
			request.setAttribute("customerMobileMulti", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", rpdao.sumTotalAmount(requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("requisitionMultiId", rmdao.getRequisitionMultiID().getRequisition_id());
			// generated auto increment id during add [E]
			
			// for get all the Product_id when add requisition [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			// for get all the Product_id when add requisition [E]
			// for get all the Customer when add requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad requisition [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when add requisition [E]
			// for get main account id when add requisition [S]
			request.setAttribute("mainAccountId", adao.getMainAccount().getAccount_id());
			// for get main account id when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		RequisitionMulti rm = new RequisitionMulti();
		
		rm.setRequisition_id(request.getParameter("requisition_id"));
		rm.setDate_time(request.getParameter("date_time"));
		rm.setCustomer_id(request.getParameter("customer_id"));
		rm.setCustomer_name(request.getParameter("customer_name"));
		rm.setMobile(request.getParameter("mobile"));
		rm.setNeeded_date_time(request.getParameter("needed_date_time"));
		rm.setFrom_account_id(request.getParameter("from_account_id"));
		rm.setTo_account_id(request.getParameter("to_account_id"));
		rm.setSalesman_id(request.getParameter("salesman_id"));
		rm.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		rm.setOrder_status(request.getParameter("order_status"));
		rm.setDelivery_status(request.getParameter("delivery_status"));
		rm.setCreated(request.getParameter("created"));
		rm.setUpdated(request.getParameter("updated"));
	
		String requisition_id = request.getParameter("requisition_id");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			rmdao.save(rm);
		} else if(action.equalsIgnoreCase("edit")){
			rm.setRequisition_id(requisition_id);
			rmdao.update(rm);
		}
		
		/*RequestDispatcher rd = request.getRequestDispatcher(LIST_REQUISITIONMULTI);*/
		RequestDispatcher rd = request.getRequestDispatcher(LIST_REQUISITIONPRODUCT);
		request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProductByMultiId(requisition_id, strDateTime));

		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());*/
		// for transfer data into another page (Product Requisition) [S]
		request.setAttribute("requisition_multi_id", requisition_id);
		request.setAttribute("strDateTimeMulti", strDateTime);
		request.setAttribute("customerNameMulti", request.getParameter("customer_name"));
		request.setAttribute("customerMobileMulti", request.getParameter("mobile"));
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", rpdao.sumTotalAmount(requisition_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
