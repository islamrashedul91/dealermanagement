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
					<li class="title"><a href="">Customer Transaction Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Customer Transaction List > Customer Transaction Product List > Customer Transaction Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Transaction Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.transaction_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Transaction ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.transaction_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Transaction Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.transaction_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.requisition_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.requisition_id}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerTransactionProduct.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.product_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.pack_type}" /></td>	
			</tr>
			
			<tr>		
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.bonus_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.order_pack}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.order_quantity}" /></td>
				<td Class ="FormCellColor" colspan="2">MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.mrp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.total_mrp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.order_status == 'P' ? 'Pending' : customerTransactionProduct.order_status == 'A' ? 'Approved' : customerTransactionProduct.order_status == 'C' ? 'Cancel' : customerTransactionProduct.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.delivery_status == 'P' ? 'Pending' : customerTransactionProduct.delivery_status == 'D' ? 'Delivered' : customerTransactionProduct.delivery_status == 'C' ? 'Cancel' : customerTransactionProduct.delivery_status == 'S' ? 'Success' : customerTransactionProduct.delivery_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Reason</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.reason}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerTransactionProduct.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerTransactionProduct.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${customerTransactionProduct.updated_by}" /></td>
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
						<a Class ="button" href="${pageContext.request.contextPath}/CustomerTransactionMainController?action=customerTransactionProductListEnquiry&transaction_id=${customerTransactionProduct.transaction_id}&requisition_id=${customerTransactionProduct.requisition_id}&date_time=${customerTransactionProduct.date_time}&customer_name=${customer_name}&mobile=${mobile}">Return</a></td>
						<%
						} else {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/CustomerTransactionMainController?action=return&transaction_id=${customerTransactionProduct.transaction_id}&requisition_id=${customerTransactionProduct.requisition_id}&date_time=${customerTransactionProduct.date_time}&customer_name=${customer_name}&mobile=${mobile}">Return</a></td>
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