import { prisma } from "../config/prisma";
import { getGoldylocksAdapter } from "../integrations/goldylocks/factory";
import { GoldylocksServiceOrder } from "../integrations/goldylocks/types";
import { logHistoryEvent } from "./historyService";
import { initializeStageInstances } from "./stageFlowService";

// ============================================================================
// Serviço de Ordens de Serviço
//
// As Ordens de Serviço são criadas no Goldylocks; este serviço trata da
// importação para a aplicação de produção (associação a cliente/produto já
// existentes, cálculo da data-limite a partir do prazo padrão do produto,
// e inicialização da linha de etapas).
//
// A criação de uma única Ordem de Serviço a partir dos dados do Goldylocks
// (`importSingleGoldylocksOrder`) é partilhada por dois caminhos de
// importação: em lote, via adaptador (mock ou API real do Goldylocks), e
// individualmente, a partir de um PDF de "Ordem Serviço" carregado pelo
// utilizador (ver `goldylocksPdfParser.ts`).
// ============================================================================

export type ImportResult =
  | { status: "created"; externalId: string }
  | { status: "skipped"; externalId: string; reason: string };

export async function importSingleGoldylocksOrder(
  goldOrder: GoldylocksServiceOrder,
  actingUserId?: string
): Promise<ImportResult> {
  const product = await prisma.product.findUnique({
    where: { externalId: goldOrder.product.externalId },
  });

  if (!product) {
    return {
      status: "skipped",
      externalId: goldOrder.externalId,
      reason: `Produto "${goldOrder.product.name}" (${goldOrder.product.externalId}) não está configurado na aplicação.`,
    };
  }

  const client = await prisma.client.upsert({
    where: { externalId: goldOrder.client.externalId },
    update: { name: goldOrder.client.name, taxNumber: goldOrder.client.taxNumber, syncedAt: new Date() },
    create: {
      externalId: goldOrder.client.externalId,
      name: goldOrder.client.name,
      taxNumber: goldOrder.client.taxNumber,
      email: goldOrder.client.email,
      phone: goldOrder.client.phone,
    },
  });

  const existing = await prisma.serviceOrder.findUnique({ where: { externalId: goldOrder.externalId } });
  if (existing) {
    return { status: "skipped", externalId: goldOrder.externalId, reason: "Já importada anteriormente." };
  }

  // A "Data de início" da OS é a data do próprio documento Goldylocks (ex.:
  // a Ordem Serviço foi criada no Goldylocks em 20/08, mas só é importada
  // para a aplicação em 21/08) — não o momento em que é importada/submetida
  // na aplicação, que seria sempre o valor por omissão (now()) do Prisma.
  const now = new Date();
  const parsedDocumentCreatedAt = new Date(goldOrder.createdAt);
  const documentCreatedAt = Number.isNaN(parsedDocumentCreatedAt.getTime()) ? now : parsedDocumentCreatedAt;

  // Por defeito, a data-limite é calculada a partir do prazo padrão do
  // produto, contado a partir da data de início (a do documento, não a da
  // importação). Quando a própria Ordem Serviço do Goldylocks já traz uma
  // data de "Prazo de entrega" impressa (caso pontual em que o prazo
  // combinado com o cliente é diferente do standard), essa data tem
  // prioridade.
  const standardDeadlineAt = new Date(
    documentCreatedAt.getTime() + product.productionDays * 24 * 60 * 60 * 1000
  );
  const deadlineFromDocument = goldOrder.deadlineAt ? new Date(goldOrder.deadlineAt) : null;
  const deadlineAt = deadlineFromDocument ?? standardDeadlineAt;

  await prisma.$transaction(async (tx) => {
    const order = await tx.serviceOrder.create({
      data: {
        externalId: goldOrder.externalId,
        clientId: client.id,
        productId: product.id,
        status: "NAO_INICIADA",
        createdAt: documentCreatedAt,
        deadlineAt,
        // Características desta encomenda (Modelo, Dimensões, Acabamento,
        // Enchimento, referência à Encomenda Cliente, etc.), tal como vieram
        // da Ordem Serviço do Goldylocks — guardadas em campo próprio para
        // serem mostradas em destaque no topo da página da OS.
        specifications: goldOrder.notes,
      },
    });

    await initializeStageInstances(order.id, product.id, tx);

    await logHistoryEvent({
      serviceOrderId: order.id,
      type: "CRIACAO",
      description: `Ordem de Serviço "${order.externalId}" importada do Goldylocks para o cliente "${client.name}".`,
      userId: actingUserId,
      tx,
    });

    if (deadlineFromDocument) {
      await logHistoryEvent({
        serviceOrderId: order.id,
        type: "OUTRA_ALTERACAO",
        description: `Data-limite definida a partir do "Prazo de entrega" indicado na Ordem Serviço (${deadlineFromDocument.toLocaleDateString(
          "pt-PT"
        )}), em vez do prazo padrão do produto.`,
        userId: actingUserId,
        tx,
      });
    }
  });

  return { status: "created", externalId: goldOrder.externalId };
}

/**
 * Importa as Ordens de Serviço novas disponibilizadas pelo Goldylocks (em
 * lote, através do adaptador configurado — mock ou API real).
 */
export async function importPendingServiceOrders(actingUserId?: string) {
  const adapter = getGoldylocksAdapter();
  const pending = await adapter.fetchNewServiceOrders();

  const created: string[] = [];
  const skipped: { externalId: string; reason: string }[] = [];

  for (const goldOrder of pending) {
    const result = await importSingleGoldylocksOrder(goldOrder, actingUserId);
    if (result.status === "created") created.push(result.externalId);
    else skipped.push({ externalId: result.externalId, reason: result.reason });
  }

  return { created, skipped };
}

/**
 * Elimina definitivamente uma Ordem de Serviço e todos os registos
 * associados (instâncias de etapas, interrupções, observações, histórico).
 * Ao contrário de `cancelServiceOrder` (que apenas muda o estado, mantendo
 * o registo para auditoria), esta operação é irreversível — reservada à
 * Administração, para remover encomendas lançadas por engano.
 */
export async function deleteServiceOrder(serviceOrderId: string) {
  const order = await prisma.serviceOrder.findUnique({ where: { id: serviceOrderId } });
  if (!order) return false;

  await prisma.$transaction(async (tx) => {
    // Quebra a referência circular (ServiceOrder.currentStageInstanceId ->
    // ServiceOrderStageInstance) antes de apagar as instâncias de etapa.
    await tx.serviceOrder.update({
      where: { id: serviceOrderId },
      data: { currentStageInstanceId: null },
    });
    await tx.attachment.deleteMany({ where: { serviceOrderId } });
    await tx.observation.deleteMany({ where: { serviceOrderId } });
    await tx.interruption.deleteMany({ where: { serviceOrderId } });
    await tx.historyEvent.deleteMany({ where: { serviceOrderId } });
    await tx.serviceOrderStageInstance.deleteMany({ where: { serviceOrderId } });
    await tx.serviceOrder.delete({ where: { id: serviceOrderId } });
  });

  return true;
}

export async function cancelServiceOrder(serviceOrderId: string, reason: string, userId?: string) {
  return prisma.$transaction(async (tx) => {
    await tx.serviceOrder.update({
      where: { id: serviceOrderId },
      data: { status: "CANCELADA" },
    });
    await logHistoryEvent({
      serviceOrderId,
      type: "ALTERACAO_ESTADO",
      description: `Ordem de Serviço cancelada. Motivo: ${reason}`,
      userId,
      tx,
    });
  });
}
