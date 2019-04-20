<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Transaction Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Transaction List > Transaction Product List > Transaction Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Transaction Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.transaction_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Transaction ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.transaction_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.purchase_product_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.purchase_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.purchase_type}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionProduct.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.product_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.pack_type}" /></td>	
			</tr>
			
			<tr>		
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.bonus_id}" /></td>
			</tr>
			
			<tr>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Rate Per Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.rate_per_piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Rate Per Box</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.rate_per_box}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.order_pack}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.order_quantity}" /></td>
				<td Class ="FormCellColor" colspan="2">TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.tp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.total_tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.order_status == 'P' ? 'Pending' : transactionProduct.order_status == 'A' ? 'Approved' : transactionProduct.order_status == 'C' ? 'Cancel' : transactionProduct.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.delivery_status == 'P' ? 'Pending' : transactionProduct.delivery_status == 'D' ? 'Delivered' : transactionProduct.delivery_status == 'C' ? 'Cancel' : transactionProduct.delivery_status == 'S' ? 'Success' : transactionProduct.delivery_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Reason</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.reason}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionProduct.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionProduct.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionProduct.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<%
						String action = (String) session.getAttribute("action");
						if (action.equalsIgnoreCase("enquiryEnquiry")) {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/TransactionMainController?action=transactionProductListEnquiry&transaction_id=${transactionProduct.transaction_id}&purchase_id=${transactionProduct.purchase_id}&date_time=${transactionProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
						<%
						} else {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/TransactionMainController?action=return&transaction_id=${transactionProduct.transaction_id}&purchase_id=${transactionProduct.purchase_id}&date_time=${transactionProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
						<%
						}
						%>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>