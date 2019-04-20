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
					<li class="title"><a href="">Purchase Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Purchase List > Purchase Product List > Purchase Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Purchase Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.purchase_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.purchase_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.purchase_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${purchaseProduct.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.product_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.pack_type}" /></td>	
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.bonus_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Rate Per Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.rate_per_piceces}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Rate Per Box</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.rate_per_box}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.order_pack}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.order_quantity}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.total_tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.discount_amt}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.total_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.order_status == 'P' ? 'Pending' : purchaseProduct.order_status == 'A' ? 'Approved' : purchaseProduct.order_status == 'C' ? 'Cancel' : purchaseProduct.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.delivery_status == 'P' ? 'Pending' : purchaseProduct.delivery_status == 'D' ? 'Delivered' : purchaseProduct.delivery_status == 'C' ? 'Cancel' : purchaseProduct.delivery_status == 'S' ? 'Success' : purchaseProduct.delivery_status == 'R' ? 'Return' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${purchaseProduct.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${purchaseProduct.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchaseProduct.updated_by}" /></td>
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
						<a Class ="button" href="${pageContext.request.contextPath}/PurchaseMainController?action=purchaseProductListEnquiry&purchase_id=${purchaseProduct.purchase_id}&date_time=${purchaseProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
						<%
						} else {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/PurchaseMainController?action=return&purchase_id=${purchaseProduct.purchase_id}&date_time=${purchaseProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
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