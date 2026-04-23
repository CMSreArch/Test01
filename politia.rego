package terraform.ec2_security

import input as tfplan

# Mensaje de error personalizado
deny[msg] {
    resource := tfplan.resource_changes[_]
    resource.type == "aws_security_group"
    
    # Obtener las reglas de entrada
    ingress := resource.change.after.ingress[_]
    
    # Verificar si el puerto 22 está en el rango
    ingress.from_port <= 22
    ingress.to_port >= 22
    
    # Verificar si el CIDR es abierto (0.0.0.0/0)
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    
    msg := sprintf("Seguridad: El grupo de seguridad '%s' permite SSH (puerto 22) desde internet (0.0.0.0/0). Esto está prohibido.", [resource.name])
}

deny[msg] {
    resource := tfplan.resource_changes[_]
    resource.type == "aws_instance"
    
    # Verificar el tipo de instancia
    instance_type := resource.change.after.instance_type
    instance_type != "t2.micro"
    
    msg := sprintf("Costos: La instancia '%s' es de tipo '%s'. Solo se permite el tipo 't2.micro'.", [resource.name, instance_type])
}
