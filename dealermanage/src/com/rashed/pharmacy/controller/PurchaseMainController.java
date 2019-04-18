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
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.dao.CompanyDAO;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.dao.ProfitLossDAO;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.CustomerPurchaseMainDAO;
import com.rashed.pharmacy.dao.CustomerTransactionMainDAO;
import com.rashed.pharmacy.model.PurchaseMain;
import com.rashed.pharmacy.dao.PurchaseMainDAO;
import com.rashed.pharmacy.dao.PurchaseProductDAO;
import com.rashed.pharmacy.dao.TransactionMainDAO;
import com.rashed.pharmacy.dao.OwnerInfoDAO;
import com.rashed.pharmacy.util.*;

public class PurchaseMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/purchaseMainAdd.jsp";
	private static String LIST_PURCHASEMAIN = "/jsp/order/purchaseMainList.jsp";
	private static String ENQUIRY = "/jsp/order/purchaseMainEnquiry.jsp";
	
	private static String LIST_PURCHASEPRODUCT = "/jsp/order/purchaseProductList.jsp";
	private static String LIST_PURCHASEPRODUCTENQUIRY = "/jsp/order/purchaseProductListEnquiry.jsp";
	
	private RequisitionMultiDAO rmdao;
	private RequisitionProductDAO rpdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	//private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	//private RequisitionProductDAO rpdao;
	private SalesMainDAO smmdao;
	private SalesProductDAO spdao;
	private CustomerPurchaseMainDAO cpmdao;
	private CustomerTransactionMainDAO ctmdao;
	private AccountDAO adao;
	private DayWiseAccountBalanceDAO dwabdao;
	private ProfitLossDAO pldao;
	
	private PurchaseMainDAO pmdao;
	private PurchaseProductDAO ppdao;
	private CompanyDAO comdao;
	private TransactionMainDAO tmdao;
	private OwnerInfoDAO odao;
	
	String action = "";
	String message = "";
	
       
    public PurchaseMainController() {
        super();
        rmdao = new RequisitionMultiDAO();
        rpdao = new RequisitionProductDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        //sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
        //rpdao = new RequisitionProductDAO();
        smmdao = new SalesMainDAO();
        spdao = new SalesProductDAO();
        cpmdao = new CustomerPurchaseMainDAO();
        ctmdao = new CustomerTransactionMainDAO();
        adao = new AccountDAO();
        dwabdao = new DayWiseAccountBalanceDAO();
        pldao = new ProfitLossDAO();
        
        pmdao = new PurchaseMainDAO();
        ppdao = new PurchaseProductDAO();
        comdao = new CompanyDAO();
        tmdao = new TransactionMainDAO();
        odao = new OwnerInfoDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String purchase_id = request.getParameter("purchase_id");
			//smmdao.delete(requisition_id);
			String strOrderStatus = pmdao.getSelectedOtherID(purchase_id).getOrder_status();
			String date_time = pmdao.getSelectedOtherID(purchase_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				pmdao.delete(purchase_id);
				message = "Purchase " + purchase_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Purchase can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = pmdao.getSelectedOtherID(purchase_id).getOrder_status();
			/*String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();*/
			
			if (!strOrderStatus.equals("A")) {
				pmdao.cancel(purchase_id);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);*/
				
				message = "Purchase " + purchase_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Purchase can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
		} else if(action.equalsIgnoreCase("approve")){
			String purchase_id = request.getParameter("purchase_id");
			String date_time = pmdao.getSelectedOtherID(purchase_id).getDate_time();
			String strOrderStatus = pmdao.getSelectedOtherID(purchase_id).getOrder_status();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				pmdao.approve(purchase_id);
				// set sales_product order_status='S' based on sales_main id [S]
				ppdao.approveByMainPurchase(purchase_id, date_time);
				// set sales_product order_status='S' based on sales_main id [E]
				
				// requisition_multi to sales_main [S]
				//smmdao.requisitionMultiToSalesMain(requisition_id, date_time);
				// requisition_multi to sales_main [E]

				// for insert into sales_product one by one from a list based on requisition_product id and date time [S]
				//rpdao.getRequisitionProductToSalesProduct(requisition_id, date_time);
				//spdao.requisitionProductToSalesProduct(requisition_id, date_time);
				// for insert into sales_product one by one from a list based on requisition_product id and date time [E]
				/*sdao.requisitionToSales(requisition_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				// for update stock one by one from a list based on requisition_multi id and date_time [S]
				/*rpdao.getProdcutIdForStockUpdate(requisition_id, date_time);*/
				// for update stock one by one from a list based on requisition_multi id and date_time [E]
				
				message = "Purchase" + purchase_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Purchase can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
		} else if(action.equalsIgnoreCase("deliveryApprove")){
			String purchase_id = request.getParameter("purchase_id");
			String strPurchaseType = pmdao.getSelectedOtherID(purchase_id).getPurchase_type();
			String strOrderStatus = pmdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strDeliveryStatus = pmdao.getSelectedOtherID(purchase_id).getDelivery_status();
			String date_time = pmdao.getSelectedOtherID(purchase_id).getDate_time();
			String strFromAccount = pmdao.getSelectedOtherID(purchase_id).getFrom_account_id();
			String strToAccount = pmdao.getSelectedOtherID(purchase_id).getTo_account_id();
			double doubleTotalAmount = pmdao.getSelectedOtherID(purchase_id).getTotal_amount();

			if (strOrderStatus.equals("A") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C")) {
				pmdao.deliveryApprove(purchase_id);
				
				ppdao.deliveryApproveByMainPurchase(purchase_id, date_time);
				
				//pdao.returnStockUpdate(strProduct, intOrderQuantity);
				ppdao.getProdcutIdForStockUpdate(purchase_id, date_time);
				
				/*cpmdao.salesMainToCustomerPurchaseMain(purchase_id, date_time);
				
				spdao.getSalesProductToCustomerPurchaseProduct(purchase_id, date_time);*/
				
				// for insert data into account table [S]
				//adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				adao.purchaseBalanceUpdate(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				//adao.purchaseBalanceUpdate(strFromAccount, doubleTotalAmount);
				// for insert data into account table [E]
				
				// for insert data into day_wise_account_balance table [S]
				/*SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);*/
				//dwabdao.dayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				dwabdao.purchaseDayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				// for insert data into profit_loss table [S]
				/*spdao.getProdcutIdForProfitLoss(purchase_id, strRequisition, date_time, strFromAccount, doubleTotalAmount, strCurrentDateTime);*/
				// for insert data into profit_loss table [E]
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				/*if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(purchase_id, date_time);
					rmdao.deleteByIdDateTime(purchase_id, date_time);
				}*/
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				/*cpdao.salesToCustomerPurchase(sales_id);
				
				//ctdao.salesToCustomerTransaction(sales_id, action);
				
				adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				// for insert data into day_wise_account_balance table [S]
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				dwabdao.dayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				// for insert data into profit_loss table [S]
				pldao.profitLossAmount(sales_id, strFromAccount, doubleTotalAmount, strProduct, intOrderQuantity, strCurrentDateTime);
				// for insert data into profit_loss table [E]
				
				rdao.delete(strRequisition);
				
				//pdao.stockUpdate(strProduct, intOrderQuantity);
*/				
				message = "Purchase " + purchase_id + " Delivered Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Purchase can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("P")) {
					message = "Without Approve Purchase can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Cancelled Delivered can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
		} else if(action.equalsIgnoreCase("deliveryReturn")){
			String purchase_id = request.getParameter("purchase_id");
			String strPurchaseType = pmdao.getSelectedOtherID(purchase_id).getPurchase_type();
			String strOrderStatus = pmdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strDeliveryStatus = pmdao.getSelectedOtherID(purchase_id).getDelivery_status();
			String date_time = pmdao.getSelectedOtherID(purchase_id).getDate_time();
			String strFromAccount = pmdao.getSelectedOtherID(purchase_id).getFrom_account_id();
			String strToAccount = pmdao.getSelectedOtherID(purchase_id).getTo_account_id();
			double doubleTotalAmount = pmdao.getSelectedOtherID(purchase_id).getTotal_amount();
			
			if (strOrderStatus.equals("A") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				pmdao.deliveryReturn(purchase_id);
				
				ppdao.deliveryReturnByMainPurchase(purchase_id, date_time);
				
				tmdao.purchaseMainToTransactionMain(purchase_id, date_time);
				
				ppdao.getPurchaseProductToTransactionProduct(purchase_id, date_time);
				/*ctmdao.salesMainToCustomerTransactionMain(purchase_id, date_time);
				
				spdao.getSalesProductToCustomerTransactionProduct(purchase_id, date_time);
				
				spdao.getProdcutIdForStockUpdate(purchase_id, date_time);*/
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				/*if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(purchase_id, date_time);
					rmdao.deleteByIdDateTime(purchase_id, date_time);
				}*/
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				ppdao.deleteByIdDateTime(purchase_id, date_time);
				pmdao.deleteByIdDateTime(purchase_id, date_time);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				//ctdao.salesToCustomerTransaction(sales_id);
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);*/
				
				message = "Purchase " + purchase_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Purchase Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("P")) {
					message = "Without Approve Purchase can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Delivery Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String purchase_id = request.getParameter("purchase_id");
			PurchaseMain pm = pmdao.getPurchaseMainById(purchase_id);
			request.setAttribute("purchaseMain", pm);
			// for get all the Product_id when update requisition [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when update requisition [E]
			// for get all company when add purchase [S]
			request.setAttribute("allCompany", comdao.getAllCompany());
			// for get all company when add purchase [E]
			// for get Owner when add requisition [S]
			request.setAttribute("allOwner", odao.getAllOwnerInfo());
			// for get Owner when add requisition [E]
			
			// selected other respective id during update [S]
			/*request.setAttribute("selectedCustomerId", pmdao.getSelectedOtherID(purchase_id).getCustomer_id());
			request.setAttribute("selectedSalesmanId", pmdao.getSelectedOtherID(purchase_id).getSalesman_id());*/
			request.setAttribute("selectedOwnerId", pmdao.getSelectedOtherID(purchase_id).getOwner_id());
			request.setAttribute("selectedCompanyId", pmdao.getSelectedOtherID(purchase_id).getCompany_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("purchaseMainList")){
			forward = LIST_PURCHASEMAIN;
			request.setAttribute("purchaseMains", pmdao.getAllPurchaseMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String purchase_id = request.getParameter("purchase_id");
			PurchaseMain pm = pmdao.getPurchaseMainById(purchase_id);
			request.setAttribute("purchaseMain", pm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_PURCHASEPRODUCT;
			
			String purchase_id = request.getParameter("purchase_id");
			String purchase_type = request.getParameter("purchase_type");
			String date_time = request.getParameter("date_time");
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProductByMainIdDateTime(purchase_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("purchase_type", purchase_type);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", ppdao.sumTotalAmount(purchase_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("purchaseProductListEnquiry")){
			forward = LIST_PURCHASEPRODUCTENQUIRY;
			
			String purchase_id = request.getParameter("purchase_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProductByMainIdDateTime(purchase_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", ppdao.sumTotalAmount(purchase_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("purchaseId", pmdao.getPurchaseMainID().getPurchase_id());
			// generated auto increment id during add [E]
			
			// for get all the Customer when add requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when add requisition [E]
			// for get all company when add purchase [S]
			request.setAttribute("allCompany", comdao.getAllCompany());
			// for get all company when add purchase [E]
			// for get Owner when add requisition [S]
			request.setAttribute("allOwner", odao.getAllOwnerInfo());
			// for get Owner when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		PurchaseMain pm = new PurchaseMain();
		
		pm.setPurchase_id(request.getParameter("purchase_id"));
		pm.setPurchase_type(request.getParameter("purchase_type"));
		pm.setDate_time(request.getParameter("date_time"));
		pm.setOwner_id(request.getParameter("owner_id"));
		pm.setOwner_name(request.getParameter("owner_name"));
		pm.setMobile(request.getParameter("mobile"));
		pm.setNeeded_date_time(request.getParameter("needed_date_time"));
		pm.setFrom_account_id(request.getParameter("from_account_id"));
		pm.setTo_account_id(request.getParameter("to_account_id"));
		pm.setCompany_id(request.getParameter("company_id"));
		pm.setCompany_name(request.getParameter("company_name"));
		pm.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		pm.setOrder_status(request.getParameter("order_status"));
		pm.setDelivery_status(request.getParameter("delivery_status"));
		pm.setCreated(request.getParameter("created"));
		pm.setUpdated(request.getParameter("updated"));
		pm.setCreated_by(request.getParameter("created_by"));
		pm.setUpdated_by(request.getParameter("updated_by"));
	
		String purchase_id = request.getParameter("purchase_id");
		String purchase_type = request.getParameter("purchase_type");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			pmdao.save(pm);
		} else if(action.equalsIgnoreCase("edit")){
			pm.setPurchase_id(purchase_id);
			pmdao.update(pm);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PURCHASEPRODUCT);
		//request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(requisition_id, strDateTime));
		request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProductByMainIdDateTime(purchase_id, strDateTime));

		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());*/
		// for transfer data into another page (Product Requisition) [S]
		request.setAttribute("purchase_id", purchase_id);
		request.setAttribute("purchase_type", purchase_type);
		request.setAttribute("strDateTime", strDateTime);
		request.setAttribute("owner_name", request.getParameter("owner_name"));
		request.setAttribute("mobile", request.getParameter("mobile"));
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", ppdao.sumTotalAmount(purchase_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
