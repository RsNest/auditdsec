package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/RsNest/auditdsec/internal/delivery"
)

func (p *Pipeline) failDelivery(err error) {
	p.log.Error("durable notification delivery stopped", "error", err)
	select {
	case p.fatal <- err:
	default:
	}
}

func (p *Pipeline) recoverDeliveries(ctx context.Context) error {
	if p.outbox == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := p.opt.Store.RecoverDeliveryPlans(p.outbox.Cursors(), func(pos delivery.Position, plan delivery.Plan) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := p.outbox.Import(pos, plan)
			if !errors.Is(err, delivery.ErrFull) {
				return err
			}
			if !p.outbox.Wait(ctx.Done()) {
				return ctx.Err()
			}
		}
	})
	if err != nil {
		p.failDelivery(err)
		return fmt.Errorf("recover journal notification plans: %w", err)
	}
	return nil
}

func (p *Pipeline) enqueueNotice(ctx context.Context, plan delivery.Plan) error {
	if len(plan.Intents) == 0 && plan.Suppressed == "" {
		return nil
	}
	if _, err := p.opt.Store.AppendDeliveryNotice(plan); err != nil {
		return err
	}
	return p.recoverDeliveries(ctx)
}

// DeliveryState contains cumulative durable outcomes and current queue occupancy.
// Failure records have safe labels only; they contain no tokens or message bodies.
func (p *Pipeline) DeliveryState() (delivery.Stats, []delivery.Failure) {
	if p.outbox == nil {
		return delivery.Stats{}, []delivery.Failure{}
	}
	return p.outbox.Stats(), p.outbox.Failures()
}
